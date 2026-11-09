//! Zone key creation, rotation and envelopes to trusted devices.

use super::*;

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
