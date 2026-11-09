//! Staging local edits and the atomic upload lifecycle.

use super::*;

impl Engine {
    /// Merges `changes` (stamped with [`Engine::tick`]) into the record and
    /// marks it for upload. A new id creates the record with `record_type`.
    pub fn stage(
        &mut self,
        zone: &str,
        record_type: &str,
        record_id: &str,
        changes: &Fields,
    ) -> Result<()> {
        if !valid_name(record_id, 128) || !valid_name(record_type, 64) {
            return Err(ClientError::InvalidRecord);
        }
        let z = self.zone_mut(zone)?;
        let local = z
            .records
            .entry(record_id.to_owned())
            .or_insert_with(|| Local {
                record_type: record_type.to_owned(),
                fields: Fields::default(),
                version: None,
                dirty: false,
                deleted: false,
                edits: 0,
            });
        if local.deleted {
            return Err(ClientError::RecordDeleted);
        }
        local.fields = merge(&local.fields, changes);
        local.dirty = true;
        local.edits += 1;
        Ok(())
    }

    /// Deletes the record everywhere. A record the server never had is only
    /// dropped here.
    pub fn delete(&mut self, zone: &str, record_id: &str) -> Result<()> {
        let z = self.zone_mut(zone)?;
        let in_flight = z
            .in_flight
            .as_ref()
            .is_some_and(|f| f.edits.contains_key(record_id));
        let Some(local) = z.records.get_mut(record_id) else {
            return Ok(());
        };
        if local.version.is_none() && !in_flight {
            z.records.remove(record_id);
            return Ok(());
        }
        local.deleted = true;
        local.fields = Fields::default();
        local.dirty = true;
        local.edits += 1;
        Ok(())
    }

    /// The next upload for the zone, or `None` when nothing waits. Until
    /// [`Engine::upload_succeeded`] or [`Engine::upload_conflicted`] is called,
    /// it returns the same batch, so resending after a lost answer is safe.
    /// Quarantined records wait until they open.
    pub fn build_upload(&mut self, zone: &str) -> Result<Option<wire::UploadChanges>> {
        let account = self.trust.account;
        let keys = &self.keys;
        if !valid_name(zone, 64) {
            return Err(ClientError::InvalidZone);
        }
        let z = self.zones.entry(zone.to_owned()).or_default();
        if let Some(flight) = &z.in_flight {
            return Ok(Some(flight.upload.clone()));
        }
        // A record deleted before the server had it needs no upload.
        z.records.retain(|_, l| !(l.deleted && l.version.is_none()));
        let dirty: Vec<String> = z
            .records
            .iter()
            .filter(|(id, l)| l.dirty && !z.quarantine.contains_key(*id))
            .map(|(id, _)| id.clone())
            .collect();
        if dirty.is_empty() {
            return Ok(None);
        }
        let (key_id, zone_key) = z.current_key().ok_or(ClientError::NoZoneKey)?;
        let mut changes = Vec::new();
        let mut edits = BTreeMap::new();
        let mut bytes = 0usize;
        for id in dirty {
            if changes.len() == MAX_BATCH {
                break;
            }
            let local = &z.records[&id];
            let place = Place {
                account: &account,
                zone,
                record_id: &id,
            };
            let change = if local.deleted {
                let Some(expected_version) = local.version else {
                    continue;
                };
                let proof = crypt::sign_delete(keys, place, expected_version, &key_id);
                wire::RecordChange::Delete {
                    record_id: id.clone(),
                    expected_version,
                    proof: Some(b64(&proof)),
                }
            } else {
                let (ciphertext, wrapped_key) = crypt::seal_record(
                    place,
                    &local.record_type,
                    local.version,
                    &local.fields,
                    &key_id,
                    zone_key,
                )?;
                if ciphertext.len() > MAX_CIPHERTEXT {
                    return Err(ClientError::RecordTooLarge);
                }
                let size = ciphertext.len() + wrapped_key.len();
                if bytes + size > MAX_BATCH_BYTES && !changes.is_empty() {
                    break;
                }
                bytes += size;
                wire::RecordChange::Save {
                    record_id: id.clone(),
                    record_type: local.record_type.clone(),
                    expected_version: local.version,
                    ciphertext: b64(&ciphertext),
                    wrapped_key: b64(&wrapped_key),
                }
            };
            edits.insert(id, local.edits);
            changes.push(change);
        }
        if changes.is_empty() {
            return Ok(None);
        }
        let upload = wire::UploadChanges {
            operation_id: uuid_v4()?,
            changes,
        };
        z.in_flight = Some(InFlight {
            upload: upload.clone(),
            edits,
        });
        Ok(Some(upload))
    }

    /// Forgets the batch waiting for an answer without applying it, for a
    /// refusal that is not a conflict. The records stay dirty.
    pub fn abandon_upload(&mut self, zone: &str) -> Result<()> {
        self.zone_mut(zone)?.in_flight = None;
        Ok(())
    }

    /// Applies the server's answer to the batch from [`Engine::build_upload`].
    pub fn upload_succeeded(&mut self, zone: &str, result: &wire::UploadResult) -> Result<()> {
        let z = self.zone_mut(zone)?;
        let flight = z.in_flight.as_ref().ok_or(ClientError::NoUpload)?;
        let matches = result.records.len() == flight.edits.len()
            && result
                .records
                .iter()
                .all(|r| flight.edits.contains_key(&r.record_id));
        if !matches {
            return Err(ClientError::Mismatch);
        }
        let flight = z.in_flight.take().ok_or(ClientError::NoUpload)?;
        for saved in &result.records {
            if saved.deleted {
                z.records.remove(&saved.record_id);
                continue;
            }
            if let Some(local) = z.records.get_mut(&saved.record_id) {
                local.version = Some(
                    local
                        .version
                        .map_or(saved.version, |v| v.max(saved.version)),
                );
                if flight.edits.get(&saved.record_id) == Some(&local.edits) {
                    local.dirty = false;
                }
            }
        }
        Ok(())
    }

    /// Applies a 409 `record_changed`: nothing was written. The batch is
    /// dropped first, whatever happens next. Each server copy is merged into
    /// the cache, and the merged records stay dirty for the next batch with the
    /// server's versions. A copy that does not open is quarantined and its
    /// record waits, so the same conflict is never sent again.
    pub fn upload_conflicted(
        &mut self,
        zone: &str,
        conflict: &wire::RecordChanged,
        now_millis: u64,
    ) -> Result<Applied> {
        let z = self.zones.get_mut(zone).ok_or(ClientError::NoUpload)?;
        if z.in_flight.take().is_none() {
            return Err(ClientError::NoUpload);
        }
        let records: Vec<(String, Option<wire::Record>)> = conflict
            .conflicts
            .iter()
            .map(|c| (c.record_id.clone(), c.server_record.clone()))
            .collect();
        Ok(self.merge_server_records(zone, records, now_millis))
    }
}
