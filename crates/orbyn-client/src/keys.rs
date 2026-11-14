//! Zone key creation, rotation and envelopes to trusted devices.

use super::*;
use orbyn_crypto::P256Point;

impl Engine {
    /// Compares one page of `GET /v1/zones` with this device's tokens. Follow
    /// `next` until it is `None` to see every zone.
    pub fn check_zones(&self, page: &wire::ZoneList) -> ZoneCheck {
        ZoneCheck {
            stale: page
                .zones
                .iter()
                .filter(|z| self.token(&z.zone) != Some(z.token.as_str()))
                .map(|z| z.zone.clone())
                .collect(),
            next: page.next.clone(),
        }
    }

    /// Makes the first key for a zone and returns its id. A zone that already
    /// has a key keeps it and returns the current key's id.
    pub fn create_zone_key(&mut self, zone: &str) -> Result<String> {
        let z = self.zone_mut(zone)?;
        if let Some(id) = z.current {
            return Ok(b64(&id));
        }
        let id: KeyId = random()?;
        z.keys.insert(id, SymmetricKey::generate()?);
        z.current = Some(id);
        Ok(b64(&id))
    }

    /// Replaces the zone's current key with a new one, signed by this device.
    /// Send it to the other devices with [`Engine::envelopes_for`].
    pub fn rotate_zone_key(&mut self, zone: &str) -> Result<String> {
        let account = self.trust.account;
        let device_id = self.trust.device_id.clone();
        let keys = &self.keys;
        let z = self.zones.get_mut(zone).ok_or(ClientError::NoZoneKey)?;
        let previous = z.current.ok_or(ClientError::NoZoneKey)?;
        let id: KeyId = random()?;
        let signature = crypt::sign_rotation(keys, &account, zone, &id, &previous);
        z.keys.insert(id, SymmetricKey::generate()?);
        z.rotations.insert(
            id,
            wire::KeyRotation {
                previous_key_id: b64(&previous),
                signer_device_id: device_id,
                signature: b64(&signature),
            },
        );
        z.current = Some(id);
        Ok(b64(&id))
    }

    /// Envelopes of every key of the zone, with their rotation records, for
    /// each device of `devices` (`GET /v1/devices`) this device verifies. A
    /// device it cannot verify gets nothing.
    pub fn envelopes_for(
        &mut self,
        zone: &str,
        devices: &wire::DeviceList,
    ) -> Result<Vec<wire::NewKeyEnvelope>> {
        let peers = self.verify_devices(devices);
        let z = self.zones.get(zone).ok_or(ClientError::NoZoneKey)?;
        if z.keys.is_empty() {
            return Err(ClientError::NoZoneKey);
        }
        let mut out = Vec::new();
        for peer in peers.iter().filter(|p| p.device_id != self.trust.device_id) {
            for (id, key) in &z.keys {
                let envelope = crypt::seal_zone_key(
                    &self.keys,
                    &peer.public,
                    &self.trust.account,
                    zone,
                    id,
                    key,
                )?;
                out.push(wire::NewKeyEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    zone: zone.to_owned(),
                    key_id: b64(id),
                    envelope: b64(&envelope),
                    rotation: z.rotations.get(id).cloned(),
                });
            }
        }
        Ok(out)
    }

    /// Service envelopes (escrow) of every key of the zone: each key sealed to the account's
    /// service key this engine verified ([`Engine::verify_service_key`]) and naming that key's
    /// statement, for `POST /v1/keychain/envelopes` or the pairs `GET
    /// /v1/keychain/service-missing` lists.
    ///
    /// The recipient is the key the engine itself checked against the log; there is no argument
    /// to seal to any other, so a certification the record server made up can never receive a zone
    /// key. With nothing verified the call refuses with
    /// [`ClientError::ServiceKeyNotVerified`] instead of sealing, and unless the newest setting
    /// this device verified says Standard it refuses with [`ClientError::ProtectionNotStandard`].
    pub fn service_envelopes_for(&self, zone: &str) -> Result<Vec<wire::NewServiceEnvelope>> {
        let verified = self
            .service_key
            .as_ref()
            .ok_or(ClientError::ServiceKeyNotVerified)?;
        let account = self.trust.account;
        let z = self.zones.get(zone).ok_or(ClientError::NoZoneKey)?;
        if z.keys.is_empty() {
            return Err(ClientError::NoZoneKey);
        }
        // Escrow only under the newest setting this device verified saying Standard: not Advanced,
        // not a setting it cannot vouch for, and not none (docs/key-service.md).
        if !self.protection_level().is_verified_standard() {
            return Err(ClientError::ProtectionNotStandard);
        }
        let service = P256Point::parse(&verified.public_key)?;
        // Rebuilt from this engine's account and the verified key, never taken from an input.
        let statement =
            orbyn_crypto::service_key_statement(verified.identity_version, &account, &service);
        let statement_hash = orbyn_crypto::service_key_statement_hash(&statement);
        let mut out = Vec::with_capacity(z.keys.len());
        let recipient = crypt::ServiceRecipient {
            service: &service,
            identity_version: verified.identity_version,
            statement_hash: &statement_hash,
        };
        for (id, key) in &z.keys {
            let envelope =
                crypt::seal_zone_key_to_service(&self.keys, &recipient, &account, zone, id, key)?;
            out.push(wire::NewServiceEnvelope {
                zone: zone.to_owned(),
                key_id: b64(id),
                envelope: b64(&envelope),
                statement_hash: b64(&statement_hash),
            });
        }
        Ok(out)
    }

    /// Opens envelopes from `GET /v1/keychain/envelopes`. Only envelopes from a
    /// device this device verifies in `devices` are opened. A key id already
    /// held keeps its key. The first key of a zone becomes current; after that
    /// the current key moves only along rotations signed by verified devices.
    pub fn accept_envelopes(
        &mut self,
        envelopes: &[wire::KeyEnvelope],
        devices: &wire::DeviceList,
    ) -> Accepted {
        let peers = self.verify_devices(devices);
        let mut accepted = Accepted::default();
        // Plain keys first, so the first key of a zone is pinned before any
        // rotation from it.
        let mut ordered: Vec<&wire::KeyEnvelope> = envelopes.iter().collect();
        ordered.sort_by_key(|e| e.rotation.is_some());
        for e in ordered {
            let reason = self.accept_one(e, &peers);
            match reason {
                Ok(true) => {
                    if !accepted.zones.contains(&e.zone) {
                        accepted.zones.push(e.zone.clone());
                    }
                }
                Ok(false) => {}
                Err(reason) => accepted.refused.push(RefusedEnvelope {
                    zone: e.zone.clone(),
                    key_id: e.key_id.clone(),
                    sender_device_id: e.sender_device_id.clone(),
                    reason: reason.to_owned(),
                }),
            }
        }
        for zone in &accepted.zones {
            if let Some(z) = self.zones.get_mut(zone) {
                z.advance();
            }
        }
        accepted
    }

    /// Ok(true) when a new key was stored.
    fn accept_one(&mut self, e: &wire::KeyEnvelope, peers: &[Peer]) -> Result<bool, &'static str> {
        let sender = peers
            .iter()
            .find(|p| p.device_id == e.sender_device_id)
            .ok_or("untrusted_sender")?;
        let id = key_id_of(&e.key_id).map_err(|_| "invalid")?;
        let bytes = unb64(&e.envelope).map_err(|_| "invalid")?;
        if !valid_name(&e.zone, 64) {
            return Err("invalid");
        }
        let key = crypt::open_zone_key(
            &self.keys,
            &sender.public,
            &self.trust.account,
            &e.zone,
            &id,
            &bytes,
        )
        .map_err(|_| "invalid")?;
        let rotation = match &e.rotation {
            None => None,
            Some(r) => {
                let previous = key_id_of(&r.previous_key_id).map_err(|_| "invalid_rotation")?;
                let signature: [u8; 64] = unb64(&r.signature)
                    .ok()
                    .and_then(|s| s.try_into().ok())
                    .ok_or("invalid_rotation")?;
                // Only a device verified and listed as trusted right now.
                let signer = peers
                    .iter()
                    .find(|p| p.device_id == r.signer_device_id)
                    .map(|p| p.public)
                    .ok_or("invalid_rotation")?;
                crypt::verify_rotation(
                    &signer,
                    &self.trust.account,
                    &e.zone,
                    &id,
                    &previous,
                    &signature,
                )
                .map_err(|_| "invalid_rotation")?;
                Some(r.clone())
            }
        };
        let z = self.zones.entry(e.zone.clone()).or_default();
        if let Some(existing) = z.keys.get(&id) {
            return if *existing == key {
                Ok(false)
            } else {
                Err("conflicting_key")
            };
        }
        z.keys.insert(id, key);
        match rotation {
            Some(r) => {
                z.rotations.insert(id, r);
            }
            None if z.current.is_none() => z.current = Some(id),
            // A second plain key (another device made one at the same time)
            // opens records but never becomes current.
            None => {}
        }
        if z.current.is_none() {
            z.current = Some(id);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use orbyn_crypto::{
        P256Keys, WrappedKeyP256, service_key_statement, service_key_statement_hash,
        unwrap_key_p256,
    };
    use orbyn_translog::verify::Seen;

    const ACCOUNT: [u8; 16] = [7; 16];
    const DEVICE: &str = "0000000a-0000-4000-8000-00000000000a";

    fn uuid(bytes: &[u8; 16]) -> String {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    }

    /// The key `verify_service_key` would hand back for `service` under identity version 1.
    fn verified(service: &P256Keys) -> VerifiedServiceKey {
        let statement = service_key_statement(1, &ACCOUNT, &service.public());
        VerifiedServiceKey {
            identity_version: 1,
            public_key: *service.public().compressed(),
            statement_hash: service_key_statement_hash(&statement),
            entry_index: 3,
            seen: Seen {
                size: 1,
                log_root: [0; 32],
                service_map_root: [0; 32],
                identity_map_root: [0; 32],
                witnessed_ms: 0,
            },
        }
    }

    /// An engine whose newest verified protection setting says `state`.
    fn engine_with(head: Option<(crate::protection::ProtectionHead, bool)>) -> Engine {
        let mut engine = engine();
        if let Some((head, complete)) = head {
            engine.protection =
                crate::protection::Protection::import(Some(&head), None, true, complete)
                    .expect("protection");
        }
        engine
    }

    fn head(level: wire::ProtectionLevel) -> crate::protection::ProtectionHead {
        crate::protection::ProtectionHead {
            seq: 1,
            level,
            hash: b64(&[1; 32]),
        }
    }

    /// An engine that verified Standard: the only one allowed to escrow.
    fn standard_engine() -> Engine {
        engine_with(Some((head(wire::ProtectionLevel::Standard), true)))
    }

    fn engine() -> Engine {
        let mut engine = Engine::new(
            DeviceKeys::generate().expect("keys"),
            &uuid(&ACCOUNT),
            DEVICE,
        )
        .expect("engine");
        engine.create_zone_key("inbox").expect("key");
        engine
    }

    #[test]
    fn every_key_of_the_zone_is_sealed_to_the_verified_service_key_and_opens_with_it() {
        let mut engine = standard_engine();
        engine.rotate_zone_key("inbox").expect("rotation");
        let service = P256Keys::generate().expect("service");
        let hash =
            service_key_statement_hash(&service_key_statement(1, &ACCOUNT, &service.public()));
        engine.service_key = Some(verified(&service));

        let envelopes = engine.service_envelopes_for("inbox").expect("envelopes");
        // The rotated key is escrowed beside the one it replaced: old records still open with it.
        assert_eq!(envelopes.len(), 2);
        for envelope in &envelopes {
            assert_eq!(envelope.zone, "inbox");
            assert_eq!(envelope.statement_hash, b64(&hash));
            let id: KeyId = unb64(&envelope.key_id)
                .expect("id")
                .try_into()
                .expect("16 bytes");
            let bytes = unb64(&envelope.envelope).expect("bytes");
            let wrapped = WrappedKeyP256::from_bytes(&bytes).expect("suite byte");
            let opened = unwrap_key_p256(
                &service,
                &engine.keys.public(),
                1,
                &hash,
                &crypt::zone_key_label(&ACCOUNT, "inbox", &id),
                &wrapped,
            )
            .expect("the service opens it");
            assert_eq!(
                opened.as_bytes(),
                engine.zones["inbox"].keys[&id].as_bytes()
            );
        }
    }

    #[test]
    fn nothing_verified_seals_nothing() {
        let engine = engine();
        assert!(matches!(
            engine.service_envelopes_for("inbox"),
            Err(ClientError::ServiceKeyNotVerified)
        ));
    }

    #[test]
    fn the_statement_is_rebuilt_from_this_account_and_the_held_key() {
        let mut engine = standard_engine();
        let service = P256Keys::generate().expect("service");
        let mut held = verified(&service);
        // A stored hash cannot choose what the envelope names: the engine rebuilds it.
        held.statement_hash = [1; 32];
        engine.service_key = Some(held);

        let envelopes = engine.service_envelopes_for("inbox").expect("envelopes");
        let hash =
            service_key_statement_hash(&service_key_statement(1, &ACCOUNT, &service.public()));
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].statement_hash, b64(&hash));
    }

    #[test]
    fn a_zone_this_device_has_no_key_for_has_nothing_to_escrow() {
        let mut engine = standard_engine();
        let service = P256Keys::generate().expect("service");
        engine.service_key = Some(verified(&service));
        assert!(matches!(
            engine.service_envelopes_for("elsewhere"),
            Err(ClientError::NoZoneKey)
        ));
    }

    /// The levels an engine can be at, and whether each may escrow.
    fn each_level() -> Vec<(&'static str, Engine, bool)> {
        use wire::ProtectionLevel::{Advanced, Standard};
        vec![
            ("advanced", engine_with(Some((head(Advanced), true))), false),
            ("unknown", engine_with(None), false),
            (
                "provisional standard",
                engine_with(Some((head(Standard), false))),
                false,
            ),
            (
                "provisional advanced",
                engine_with(Some((head(Advanced), false))),
                false,
            ),
            ("verified standard", standard_engine(), true),
        ]
    }

    #[test]
    fn escrow_needs_a_verified_standard_setting_and_nothing_else_seals() {
        let service = P256Keys::generate().expect("service");
        for (name, mut engine, allowed) in each_level() {
            // A service key is verified in every case: it is the protection level that decides.
            engine.service_key = Some(verified(&service));
            let sealed = engine.service_envelopes_for("inbox");
            if allowed {
                assert_eq!(sealed.expect(name).len(), 1, "{name}");
            } else {
                assert_eq!(
                    sealed.err(),
                    Some(ClientError::ProtectionNotStandard),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn a_verified_standard_engine_with_no_service_key_still_seals_nothing() {
        assert!(matches!(
            standard_engine().service_envelopes_for("inbox"),
            Err(ClientError::ServiceKeyNotVerified)
        ));
    }
}
