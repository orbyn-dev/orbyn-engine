//! Engine construction, snapshots, clocks and local record access.

use super::*;

impl Engine {
    /// A new engine for the device `device_id` of `account_id` (both UUIDs, as
    /// the server gave them at sign-up or sign-in).
    pub fn new(keys: DeviceKeys, account_id: &str, device_id: &str) -> Result<Self> {
        let account = uuid_bytes(account_id)?;
        uuid_bytes(device_id)?;
        let me = keys.public();
        Ok(Self {
            clock: Clock::new(stamp_device(&me)),
            trust: Trust::new(account, device_id.to_owned(), me),
            protection: protection::Protection::default(),
            service_key: None,
            service_key_history_unknown: false,
            keys,
            zones: BTreeMap::new(),
            skipped_future_stamps: 0,
        })
    }

    /// Restores an engine from [`Engine::snapshot`]. `now_millis` moves the
    /// clock past every stamp in the cache.
    pub fn restore(keys: DeviceKeys, snapshot: Snapshot, now_millis: u64) -> Result<Self> {
        let mut engine = Self::new(keys, &snapshot.account_id, &snapshot.device_id)?;
        engine.trust.import(&snapshot.pinned, &snapshot.revoked)?;
        engine
            .trust
            .set_removal_sequence(snapshot.removal_sequence.min(auth::MAX_REMOVAL_SEQUENCE));
        engine.protection = protection::Protection::import(
            snapshot.protection.as_ref(),
            snapshot.protection_floor.as_ref(),
            snapshot.protection_anchored,
            snapshot.protection_complete,
        )?;
        match snapshot.service_key.as_ref() {
            Some(held) => engine.service_key = Some(held.restore()?),
            // An older snapshot: nothing says whether a key was ever verified.
            None => engine.service_key_history_unknown = !snapshot.service_key_tracked,
        }
        for (name, z) in snapshot.zones {
            let mut keys = BTreeMap::new();
            for (id, key) in &z.keys {
                let bytes: [u8; 32] = unb64(key)?
                    .try_into()
                    .map_err(|_| ClientError::InvalidInput)?;
                keys.insert(key_id_of(id)?, SymmetricKey::from_bytes(bytes));
            }
            let mut rotations = BTreeMap::new();
            for (id, r) in z.rotations {
                rotations.insert(key_id_of(&id)?, r);
            }
            for local in z.records.values() {
                if let Some(latest) = local.fields.latest()
                    && engine.clock.resume(latest, now_millis).is_err()
                {
                    // More than an hour ahead of this clock: it must not drag
                    // the clock there. The record stays; the host is told.
                    engine.skipped_future_stamps += 1;
                }
            }
            engine.zones.insert(
                name,
                ZoneState {
                    keys,
                    current: z.current.as_deref().map(key_id_of).transpose()?,
                    rotations,
                    token: z.token,
                    records: z.records,
                    in_flight: z.in_flight,
                    quarantine: z.quarantine,
                    trash: z.trash,
                    refetch: z.refetch,
                    refetch_restarts: z.refetch_restarts,
                },
            );
        }
        Ok(engine)
    }

    pub fn snapshot(&self) -> Snapshot {
        let zones = self
            .zones
            .iter()
            .map(|(name, z)| {
                let snapshot = ZoneSnapshot {
                    keys: z
                        .keys
                        .iter()
                        .map(|(id, key)| (b64(id), b64(key.as_bytes())))
                        .collect(),
                    current: z.current.map(|id| b64(&id)),
                    rotations: z
                        .rotations
                        .iter()
                        .map(|(id, r)| (b64(id), r.clone()))
                        .collect(),
                    token: z.token.clone(),
                    records: z.records.clone(),
                    quarantine: z.quarantine.clone(),
                    trash: z.trash.clone(),
                    in_flight: z.in_flight.clone(),
                    refetch: z.refetch.clone(),
                    refetch_restarts: z.refetch_restarts,
                };
                (name.clone(), snapshot)
            })
            .collect();
        let (pinned, revoked) = self.trust.export();
        let protection = self.protection.export();
        Snapshot {
            account_id: format_uuid(&self.trust.account),
            device_id: self.trust.device_id.clone(),
            pinned,
            revoked,
            removal_sequence: self.trust.removal_sequence(),
            protection: protection.head,
            protection_floor: protection.floor,
            protection_anchored: protection.anchored,
            protection_complete: protection.complete,
            service_key: self.service_key.as_ref().map(HeldServiceKey::from),
            service_key_tracked: true,
            zones,
        }
    }

    pub fn device_keys(&self) -> &DeviceKeys {
        &self.keys
    }

    /// The account this engine belongs to.
    pub fn account(&self) -> [u8; 16] {
        self.trust.account
    }

    pub fn device_id(&self) -> &str {
        &self.trust.device_id
    }

    /// The devices of `list` (`GET /v1/devices`) this device trusts: trusted
    /// on the server and linked by approval signatures to a device it already
    /// trusts. See the `trust` module.
    pub fn verify_devices(&mut self, list: &wire::DeviceList) -> Vec<Peer> {
        self.trust.verify(list)
    }

    /// Trusts a device the person checked another way, such as by comparing
    /// keys on both screens.
    pub fn pin_device(&mut self, device_id: &str, public: DevicePublic) -> Result<()> {
        self.trust.pin_anchor(device_id, public)
    }

    /// The `DELETE /v1/devices/{id}` body that removes `device` (from
    /// `GET /v1/devices`), signed by this device with a sequence one above
    /// every removal it has counted.
    pub fn sign_removal(&self, device: &wire::Device) -> Result<wire::RemoveDevice> {
        let keys = trust::public_of(device).ok_or(ClientError::InvalidInput)?;
        let sequence = (self.trust.removal_sequence() + 1).min(auth::MAX_REMOVAL_SEQUENCE);
        let message = orbyn_auth_client::removal_message(
            &self.trust.account,
            &uuid_bytes(&device.id)?,
            &keys,
            sequence,
        );
        Ok(wire::RemoveDevice {
            sequence,
            signature: b64(&self
                .keys
                .sign(orbyn_auth_client::DEVICE_REMOVAL_CONTEXT, &message)),
        })
    }

    /// The `DELETE /v1/zones/{zone}` body: this device's signature that every
    /// record of the zone up to the newest version it has seen is deleted.
    /// Records written after that keep a tombstone devices do not accept.
    pub fn delete_zone_proof(&self, zone: &str) -> Result<wire::DeleteZone> {
        let z = self.zones.get(zone).ok_or(ClientError::InvalidZone)?;
        let through = z
            .records
            .values()
            .filter_map(|l| l.version)
            .chain(z.quarantine.values().map(|q| q.record.version))
            .max()
            .unwrap_or(0);
        let proof = crypt::sign_zone_delete(&self.keys, &self.trust.account, zone, through);
        Ok(wire::DeleteZone {
            proof: Some(b64(&proof)),
        })
    }

    /// The stamp for a new local edit at wall time `now_millis`.
    pub fn tick(&mut self, now_millis: u64) -> Stamp {
        self.clock.tick(now_millis)
    }

    /// The stamp for an edit the person made at `edit_millis`, which may be
    /// earlier than `now_millis` (an edit queued while the app was closed). The
    /// clock's rules still hold: the stamp can never be earlier than the last
    /// one this device issued or saw, so an older `edit_millis` is moved up to
    /// just after it. An edit cannot have been made in the future, so an
    /// `edit_millis` after `now_millis` is taken as `now_millis`, silently: a
    /// device whose clock runs a little fast does not fail its own edits, and
    /// never issues a stamp that other devices would drop as too far ahead.
    pub fn tick_at(&mut self, edit_millis: u64, now_millis: u64) -> Stamp {
        self.clock.tick(edit_millis.min(now_millis))
    }

    /// How many records the last [`Engine::restore`] found with a newest stamp
    /// more than an hour ahead of its `now_millis`. Such a stamp is not allowed
    /// to move the clock; the records are kept. The engine does no logging, so
    /// a host should log a non-zero count (the clock of this or another device
    /// is wrong).
    pub fn skipped_future_stamps(&self) -> usize {
        self.skipped_future_stamps
    }

    pub(super) fn zone_mut(&mut self, zone: &str) -> Result<&mut ZoneState> {
        if !valid_name(zone, 64) {
            return Err(ClientError::InvalidZone);
        }
        Ok(self.zones.entry(zone.to_owned()).or_default())
    }

    /// Zones this device knows, by name.
    pub fn zones(&self) -> impl Iterator<Item = &str> {
        self.zones.keys().map(String::as_str)
    }

    /// The change token to fetch from; `None` fetches from the start.
    pub fn token(&self, zone: &str) -> Option<&str> {
        self.zones.get(zone)?.token.as_deref()
    }

    /// A live record's fields.
    pub fn record(&self, zone: &str, record_id: &str) -> Option<&Fields> {
        let local = self.zones.get(zone)?.records.get(record_id)?;
        (!local.deleted).then_some(&local.fields)
    }

    /// A live record's type, as stored.
    pub fn record_type(&self, zone: &str, record_id: &str) -> Option<&str> {
        let local = self.zones.get(zone)?.records.get(record_id)?;
        (!local.deleted).then_some(local.record_type.as_str())
    }

    /// Every cached record of the zone, deleted ones waiting to upload included.
    pub fn records(&self, zone: &str) -> impl Iterator<Item = (&str, &Local)> {
        self.zones
            .get(zone)
            .into_iter()
            .flat_map(|z| z.records.iter().map(|(id, l)| (id.as_str(), l)))
    }

    pub fn quarantine(&self, zone: &str) -> impl Iterator<Item = (&str, &Quarantined)> {
        self.zones
            .get(zone)
            .into_iter()
            .flat_map(|z| z.quarantine.iter().map(|(id, q)| (id.as_str(), q)))
    }

    pub fn trash(&self, zone: &str) -> impl Iterator<Item = (&str, &Trashed)> {
        self.zones
            .get(zone)
            .into_iter()
            .flat_map(|z| z.trash.iter().map(|(id, t)| (id.as_str(), t)))
    }

    /// Takes a record out of the trash, for the host to keep under a new id.
    pub fn take_from_trash(&mut self, zone: &str, record_id: &str) -> Option<Trashed> {
        self.zones.get_mut(zone)?.trash.remove(record_id)
    }

    /// The id of the key new records of the zone are sealed with.
    pub fn current_key_id(&self, zone: &str) -> Option<String> {
        self.zones.get(zone)?.current.map(|id| b64(&id))
    }

    /// True when the zone has local changes the server does not have yet.
    pub fn has_pending(&self, zone: &str) -> bool {
        self.zones.get(zone).is_some_and(|z| {
            // A record waiting behind a quarantined server copy still has
            // edits the server lacks.
            z.in_flight.is_some() || z.records.values().any(|l| l.dirty)
        })
    }
}
