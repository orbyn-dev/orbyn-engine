//! Incoming pages, merges, quarantine and refetch handling.

use super::*;

impl Engine {
    /// Opens and merges one page of `GET /v1/zones/{zone}/changes` and moves
    /// the token on. Records that do not open are quarantined.
    ///
    /// While a zone is being fetched again after [`Engine::token_expired`] this
    /// returns [`ClientError::Mismatch`]: use [`Engine::apply_changes_from`],
    /// which can tell the refetch's own pages from any other.
    pub fn apply_changes(
        &mut self,
        zone: &str,
        page: &wire::ZoneChanges,
        now_millis: u64,
    ) -> Result<Applied> {
        if self.zone_mut(zone)?.refetch.is_some() {
            return Err(ClientError::Mismatch);
        }
        self.apply_page(zone, page, now_millis)
    }

    /// Like [`Engine::apply_changes`], for a page fetched with `since` (the
    /// `since` query of the request, `None` for a fetch from the start). A page
    /// fetched with any other token than the engine's current one is stale, for
    /// example an answer that arrived after [`Engine::token_expired`], and is
    /// refused with [`ClientError::Mismatch`] without changing anything. A
    /// refetch ends only on the last page of its own fetch.
    pub fn apply_changes_from(
        &mut self,
        zone: &str,
        since: Option<&str>,
        page: &wire::ZoneChanges,
        now_millis: u64,
    ) -> Result<Applied> {
        if self.zone_mut(zone)?.token.as_deref() != since {
            return Err(ClientError::Mismatch);
        }
        self.apply_page(zone, page, now_millis)
    }

    fn apply_page(
        &mut self,
        zone: &str,
        page: &wire::ZoneChanges,
        now_millis: u64,
    ) -> Result<Applied> {
        let records: Vec<(String, Option<wire::Record>)> = page
            .records
            .iter()
            .map(|r| (r.record_id.clone(), Some(r.clone())))
            .collect();
        let mut applied = self.merge_server_records(zone, records, now_millis);
        if let Some(z) = self.zones.get_mut(zone) {
            z.token = Some(page.token.clone());
            if let Some(unseen) = z.refetch.as_mut() {
                for record in &page.records {
                    unseen.remove(&record.record_id);
                }
            }
            if !page.more {
                Self::finish_refetch(z, &mut applied, now_millis);
            }
        }
        applied.more = page.more;
        Ok(applied)
    }

    /// Call when the server answers `token_expired` to a fetch or an upload of
    /// the zone: tombstones this device has not seen were purged. It forgets
    /// the zone's token and any upload waiting for an answer, so
    /// [`Engine::token`] is `None` and the host fetches the zone from the start
    /// (without `since`), page by page as usual. Local edits are kept.
    ///
    /// Once the last page is applied, a record this device held at a server
    /// version that the full listing no longer has was deleted and purged. As
    /// with any delete, it wins over local edits: the copy, edits included, goes
    /// to the trash for 30 days (listed in `trashed`) and is not uploaded again.
    /// No tombstone is left to verify, so the trash is what keeps a wrong
    /// answer from losing data.
    ///
    /// If the zone expires again while a refetch is running (the server purged
    /// more before it ended, so its page tokens expired), the refetch starts
    /// over from the beginning with the records it still has to check kept, so
    /// none is trashed early. After [`MAX_REFETCH_RESTARTS`] restarts in a row
    /// this returns [`ClientError::ExpiredAgain`] with the state already reset
    /// to a clean start, so the host can stop and the next sync begins afresh
    /// instead of getting stuck on a token the server no longer accepts.
    pub fn token_expired(&mut self, zone: &str) -> Result<()> {
        let z = self.zone_mut(zone)?;
        z.token = None;
        z.in_flight = None;
        let held = z
            .records
            .iter()
            .filter(|(_, local)| local.version.is_some())
            .map(|(id, _)| id.clone());
        let again = z.refetch.is_some();
        // Records already seen in the abandoned run stay to be checked: the
        // restart lists them again, and one deleted and purged meanwhile is
        // then caught like the rest.
        let mut unseen = z.refetch.take().unwrap_or_default();
        unseen.extend(held);
        z.refetch = Some(unseen);
        // A refetch that ends, or is given up with ExpiredAgain, resets the
        // count, so a refetch that starts here always starts at zero.
        if !again {
            return Ok(());
        }
        if z.refetch_restarts >= MAX_REFETCH_RESTARTS {
            z.refetch_restarts = 0;
            return Err(ClientError::ExpiredAgain);
        }
        z.refetch_restarts += 1;
        Ok(())
    }

    /// Ends a refetch after its last page, settling the records it did not list.
    fn finish_refetch(z: &mut ZoneState, applied: &mut Applied, now_millis: u64) {
        z.refetch_restarts = 0;
        let Some(unseen) = z.refetch.take() else {
            return;
        };
        for id in unseen {
            let Some(local) = z.records.get_mut(&id) else {
                continue;
            };
            if local.deleted {
                // Already deleted here and the server has nothing left to delete.
                z.records.remove(&id);
            } else if let Some(local) = z.records.remove(&id) {
                // Clean or edited alike: a delete wins over edits everywhere, so
                // the edits are in the trash, not uploaded as a new record.
                z.trash.insert(
                    id.clone(),
                    Trashed {
                        record_type: local.record_type,
                        fields: local.fields,
                        deleted_by: "purge".to_owned(),
                        deleted_at_millis: now_millis,
                    },
                );
                applied.trashed.push(id.clone());
                applied.removed.push(id);
            }
        }
    }

    /// Tries every quarantined record of the zone again, after new keys or
    /// trusted devices arrived.
    pub fn retry_quarantined(&mut self, zone: &str, now_millis: u64) -> Applied {
        let Some(z) = self.zones.get_mut(zone) else {
            return Applied::default();
        };
        let mut records: Vec<wire::Record> = std::mem::take(&mut z.quarantine)
            .into_values()
            .map(|q| q.record)
            .collect();
        records.sort_by_key(|r| r.version);
        let records = records
            .into_iter()
            .map(|r| (r.record_id.clone(), Some(r)))
            .collect();
        self.merge_server_records(zone, records, now_millis)
    }

    fn classify(&self, zone: &str, id: &str, record: Option<wire::Record>) -> Option<Copy> {
        let z = self.zones.get(zone)?;
        let Some(r) = record else {
            return Some(Copy::Never);
        };
        let place = Place {
            account: &self.trust.account,
            zone,
            record_id: id,
        };
        // Anything not newer than what this device has is old news, a replayed
        // tombstone included.
        let known = z.records.get(id).and_then(|l| l.version);
        if known.is_some_and(|v| v >= r.version) {
            return None;
        }
        if r.deleted {
            let verified = r
                .delete_proof
                .as_deref()
                .and_then(|p| unb64(p).ok())
                .zip(self.trust.pinned(&r.author_device_id))
                .is_some_and(|(proof, author)| {
                    crypt::verify_delete(author, place, r.version, known.unwrap_or(0), &proof)
                        .is_ok()
                });
            return Some(Copy::Tombstone {
                verified,
                author: r.author_device_id,
            });
        }
        let bytes = r
            .ciphertext
            .as_deref()
            .zip(r.wrapped_key.as_deref())
            .and_then(|(ct, wk)| Some((unb64(ct).ok()?, unb64(wk).ok()?)));
        let Some((ct, wk)) = bytes else {
            return Some(Copy::Unreadable(r, "invalid_record"));
        };
        match crypt::open_record(place, &r.record_type, r.version, &ct, &wk, &z.keys) {
            Ok(fields) => Some(Copy::Live(fields, r.version, r.record_type)),
            Err(ClientError::MissingZoneKey { .. }) => {
                Some(Copy::Unreadable(r, "missing_zone_key"))
            }
            Err(ClientError::Decode) => Some(Copy::Unreadable(r, "invalid_record")),
            Err(_) => Some(Copy::Unreadable(r, "open_failed")),
        }
    }

    /// Merges server copies into the cache, one at a time; a copy that does
    /// not open or verify never stops the others.
    pub(super) fn merge_server_records(
        &mut self,
        zone: &str,
        records: Vec<(String, Option<wire::Record>)>,
        now_millis: u64,
    ) -> Applied {
        let mut applied = Applied::default();
        for (id, record) in records {
            let version = record.as_ref().map(|r| r.version);
            let Some(copy) = self.classify(zone, &id, record) else {
                continue;
            };
            let Some(z) = self.zones.get_mut(zone) else {
                break;
            };
            match copy {
                Copy::Never => {
                    if let Some(local) = z.records.get_mut(&id) {
                        local.version = None;
                        local.dirty = true;
                        local.edits += 1;
                    }
                }
                Copy::Unreadable(record, reason) => {
                    let newer = z
                        .quarantine
                        .get(&id)
                        .is_none_or(|q| q.record.version <= record.version);
                    if newer {
                        z.quarantine.insert(
                            id.clone(),
                            Quarantined {
                                record,
                                reason: reason.to_owned(),
                            },
                        );
                    }
                    applied.quarantined.push(id);
                    applied.evicted.extend(z.trim_quarantine());
                }
                Copy::Tombstone {
                    verified: false, ..
                } => {
                    // Not proven by a trusted device: keep the record, and put
                    // the local copy back on the server over the tombstone.
                    if let Some(local) = z.records.get_mut(&id) {
                        local.version = version;
                        local.dirty = true;
                        local.edits += 1;
                    }
                    applied.unverified_deletes.push(id);
                }
                Copy::Tombstone {
                    verified: true,
                    author,
                } => {
                    z.quarantine.remove(&id);
                    if let Some(local) = z.records.remove(&id) {
                        if local.dirty && !local.deleted {
                            z.trash.insert(
                                id.clone(),
                                Trashed {
                                    record_type: local.record_type,
                                    fields: local.fields,
                                    deleted_by: author,
                                    deleted_at_millis: now_millis,
                                },
                            );
                            applied.trashed.push(id.clone());
                        }
                        applied.removed.push(id);
                    }
                }
                Copy::Live(theirs, version, record_type) => {
                    if z.quarantine
                        .get(&id)
                        .is_some_and(|q| q.record.version <= version)
                    {
                        z.quarantine.remove(&id);
                    }
                    let merged = merge_remote(&Fields::default(), &theirs, now_millis);
                    for field in merged.fields.0.values() {
                        let _ = self.clock.observe(field.stamp, now_millis);
                    }
                    if !merged.rejected.is_empty() {
                        applied.rejected.push(RejectedFields {
                            record_id: id.clone(),
                            fields: merged.rejected.clone(),
                        });
                    }
                    match z.records.get_mut(&id) {
                        Some(local) => {
                            local.version = Some(version);
                            if local.deleted {
                                // Our delete still wins; send it with the new version.
                                local.dirty = true;
                                local.edits += 1;
                                continue;
                            }
                            let next = merge(&local.fields, &merged.fields);
                            let dirty = next != theirs;
                            if next != local.fields {
                                applied.changed.push(id.clone());
                            }
                            if next != local.fields || dirty != local.dirty {
                                local.edits += 1;
                            }
                            local.fields = next;
                            local.dirty = dirty;
                        }
                        None => {
                            let dirty = merged.fields != theirs;
                            applied.changed.push(id.clone());
                            z.records.insert(
                                id,
                                Local {
                                    record_type,
                                    fields: merged.fields,
                                    version: Some(version),
                                    dirty,
                                    deleted: false,
                                    edits: 0,
                                },
                            );
                        }
                    }
                }
            }
        }
        if let Some(z) = self.zones.get_mut(zone) {
            z.trash
                .retain(|_, t| now_millis.saturating_sub(t.deleted_at_millis) < TRASH_MILLIS);
        }
        applied
    }
}
