//! Sync: open the engine, then push and pull per zone, hand out and take in zone keys, and keep
//! the status current. The records go in and out as plain fields (`orbyn_sync::Fields`); sealing,
//! opening and the zone keys are inside `orbyn_client::Engine`, whose `Snapshot` the host stores
//! sealed under the vault key.

use crate::api::Method;
use crate::client::{DeviceClient, failure, is_ok, json, parse};
use crate::error::DeviceError;
use crate::status::{SyncState, SyncStatus};
use crate::{Clock, DeviceApi, KeyStore};
use orbyn_client::{Applied, ClientError, Engine, RefusedEnvelope, Snapshot};
use orbyn_contracts as wire;

/// How many conflicts one zone's upload merges inside a pass before the pass gives up on it.
const MAX_CONFLICT_ROUNDS: usize = 8;
/// How many times one zone may start again (a 410) inside a pass, on a pull or an upload.
const MAX_RESTARTS: usize = 3;
/// A safety stop on the batches one pass sends for one zone (each holds up to 200 records).
const MAX_BATCHES: usize = 1000;
/// The most envelopes one request carries.
const ENVELOPES_PER_REQUEST: usize = 100;

/// What a pass did to one zone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZoneReport {
    pub zone: String,
    /// What came in from the server.
    pub applied: Applied,
    /// Records this device uploaded.
    pub pushed: usize,
    /// The zone has changes to upload and this device has no key for it yet: another device sends
    /// it. Nothing is lost; the next pass tries again.
    pub waiting_for_key: bool,
}

/// What a whole pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub zones: Vec<ZoneReport>,
    /// Zones that got a new key from another device.
    pub keys_accepted: Vec<String>,
    /// Envelopes this device refused, and why.
    pub keys_refused: Vec<RefusedEnvelope>,
}

pub(crate) fn engine_error(error: ClientError) -> DeviceError {
    match error {
        ClientError::RecordTooLarge => DeviceError::TooLarge,
        ClientError::NoZoneKey => DeviceError::NoZoneKey,
        other => DeviceError::Engine(other.to_string()),
    }
}

/// A path segment, percent-encoded: zone names and tokens may hold `:` or `.`.
pub(crate) fn segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn merge(into: &mut Applied, from: Applied) {
    into.changed.extend(from.changed);
    into.removed.extend(from.removed);
    into.trashed.extend(from.trashed);
    into.quarantined.extend(from.quarantined);
    into.unverified_deletes.extend(from.unverified_deletes);
    into.evicted.extend(from.evicted);
    into.rejected.extend(from.rejected);
    into.more = from.more;
}

impl<A: DeviceApi, S: KeyStore, C: Clock> DeviceClient<A, S, C> {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.clock.now_secs()).unwrap_or(0) * 1000
    }

    /// The status: `Idle`, `Syncing`, `Offline`, and the states that need the host to act. The
    /// latest value is always there.
    pub fn status(&self) -> tokio::sync::watch::Receiver<SyncStatus> {
        self.status.subscribe()
    }

    fn set_state(&self, state: SyncState) {
        self.status.send_modify(|s| s.state = state);
    }

    /// Opens the sync engine for this device: from the host's sealed snapshot, or empty the
    /// first time. The snapshot holds the zone keys and the cache, and belongs to this device and
    /// account only.
    pub fn open_engine(&self, snapshot: Option<Snapshot>) -> Result<Engine, DeviceError> {
        let identity = self.store.load()?.ok_or(DeviceError::NotSignedIn)?;
        let keys = identity.keys()?;
        match snapshot {
            Some(snapshot) => {
                if snapshot.account_id != identity.account_id
                    || snapshot.device_id != identity.device_id
                {
                    return Err(DeviceError::InvalidInput(
                        "the snapshot belongs to another account or device",
                    ));
                }
                Engine::restore(keys, snapshot, self.now_millis())
            }
            None => Engine::new(keys, &identity.account_id, &identity.device_id),
        }
        .map_err(engine_error)
    }

    /// The account's devices, as the server lists them. The engine checks the approvals itself.
    pub async fn devices(&self) -> Result<wire::DeviceList, DeviceError> {
        let response = self.authed(Method::Get, "/v1/devices", None).await?;
        parse(&response.body)
    }

    /// One pass over the whole account: the device list, the zone keys other devices sent, then
    /// every zone that changed on the server or has local changes, pulled and pushed. A failure
    /// of the network is [`DeviceError::Transport`] and changes nothing: whatever was staged
    /// stays staged, and the next pass sends it. The status reflects the result either way.
    pub async fn sync_all(&self, engine: &mut Engine) -> Result<SyncReport, DeviceError> {
        self.set_state(SyncState::Syncing);
        let result = self.sync_all_inner(engine).await;
        let now = self.clock.now_secs();
        match &result {
            Ok(_) => self.status.send_modify(|s| {
                s.state = SyncState::Idle;
                s.last_synced = Some(now);
                s.last_error = None;
            }),
            Err(error) => self.status.send_modify(|s| *s = s.after(error, now)),
        }
        result
    }

    async fn sync_all_inner(&self, engine: &mut Engine) -> Result<SyncReport, DeviceError> {
        let now = self.now_millis();
        // The engine verifies the devices itself when it takes keys in and hands them out.
        let devices = self.devices().await?;
        let mut report = SyncReport::default();

        // Keys other devices sent come first, so what could not be opened can be.
        let envelopes: wire::KeyEnvelopeList = parse(
            &self
                .authed(Method::Get, "/v1/keychain/envelopes", None)
                .await?
                .body,
        )?;
        let accepted = engine.accept_envelopes(&envelopes.envelopes, &devices);
        for zone in &accepted.zones {
            engine.retry_quarantined(zone, now);
        }
        report.keys_accepted = accepted.zones;
        report.keys_refused = accepted.refused;

        // The zones on the server, and which differ from this device's view.
        let mut on_server: Vec<(String, bool)> = Vec::new();
        let mut stale: Vec<String> = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let path = match &after {
                Some(after) => format!("/v1/zones?after={}", segment(after)),
                None => "/v1/zones".to_owned(),
            };
            let page: wire::ZoneList = parse(&self.authed(Method::Get, &path, None).await?.body)?;
            let check = engine.check_zones(&page);
            stale.extend(check.stale);
            on_server.extend(page.zones.iter().map(|z| (z.zone.clone(), z.deleted)));
            match check.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }

        // Zones with local changes, and zones made here that the server does not have yet.
        let mut work: Vec<String> = stale;
        for zone in engine.zones().map(str::to_owned).collect::<Vec<_>>() {
            if engine.has_pending(&zone) && !work.contains(&zone) {
                work.push(zone);
            }
        }
        work.sort();
        for zone in work {
            let exists = on_server
                .iter()
                .any(|(name, deleted)| *name == zone && !deleted);
            if !exists && engine.has_pending(&zone) {
                self.make_zone(engine, &zone, &devices).await?;
            }
            report.zones.push(self.sync_zone(engine, &zone).await?);
        }
        Ok(report)
    }

    /// Makes a zone on the server and, if this device has no key for it, a key; then hands the
    /// key to the account's other trusted devices.
    async fn make_zone(
        &self,
        engine: &mut Engine,
        zone: &str,
        devices: &wire::DeviceList,
    ) -> Result<(), DeviceError> {
        self.authed(Method::Put, &format!("/v1/zones/{}", segment(zone)), None)
            .await?;
        engine.create_zone_key(zone).map_err(engine_error)?;
        self.send_keys(engine, zone, devices).await
    }

    /// Seals every key of `zone` to each trusted device of the account that this device
    /// verifies, and sends the envelopes. A zone nobody else needs yet sends nothing.
    pub async fn send_keys(
        &self,
        engine: &mut Engine,
        zone: &str,
        devices: &wire::DeviceList,
    ) -> Result<(), DeviceError> {
        let envelopes = engine.envelopes_for(zone, devices).map_err(engine_error)?;
        for chunk in envelopes.chunks(ENVELOPES_PER_REQUEST) {
            let body = json(&wire::PutKeyEnvelopes {
                envelopes: chunk.to_vec(),
                service_envelopes: None,
            })?;
            self.authed(Method::Post, "/v1/keychain/envelopes", Some(body))
                .await?;
        }
        Ok(())
    }

    /// Pulls, then pushes, one zone.
    pub async fn sync_zone(
        &self,
        engine: &mut Engine,
        zone: &str,
    ) -> Result<ZoneReport, DeviceError> {
        let mut report = ZoneReport {
            zone: zone.to_owned(),
            ..ZoneReport::default()
        };
        for _ in 0..MAX_RESTARTS {
            self.pull(engine, zone, &mut report.applied).await?;
            match self.push(engine, zone, &mut report).await {
                Ok(false) => return Ok(report),
                // An upload was told the token is too old: the zone starts again, then goes up.
                Ok(true) => {}
                Err(DeviceError::NoZoneKey) => {
                    report.waiting_for_key = true;
                    return Ok(report);
                }
                Err(error) => return Err(error),
            }
        }
        Err(DeviceError::Server {
            status: 410,
            code: "token_expired".to_owned(),
        })
    }

    async fn pull(
        &self,
        engine: &mut Engine,
        zone: &str,
        applied: &mut Applied,
    ) -> Result<(), DeviceError> {
        let mut restarts = 0;
        loop {
            let since = engine.token(zone).map(str::to_owned);
            let mut path = format!("/v1/zones/{}/changes?limit=200", segment(zone));
            if let Some(token) = &since {
                path.push_str(&format!("&since={}", segment(token)));
            }
            let response = self.authed_raw(Method::Get, &path, None).await?;
            match response.status {
                200 => {}
                // The server purged history this device has not seen: fetch from the start.
                410 => {
                    restarts += 1;
                    if restarts > MAX_RESTARTS {
                        return Err(failure(&response));
                    }
                    engine.token_expired(zone).map_err(engine_error)?;
                    continue;
                }
                // Not made yet, or deleted: nothing to pull.
                404 | 409 => return Ok(()),
                _ => return Err(failure(&response)),
            }
            let changes: wire::ZoneChanges = parse(&response.body)?;
            // `apply_changes_from` also serves the pages of a fetch that starts again.
            let page = engine
                .apply_changes_from(zone, since.as_deref(), &changes, self.now_millis())
                .map_err(engine_error)?;
            let more = changes.more;
            merge(applied, page);
            if !more {
                return Ok(());
            }
        }
    }

    async fn push(
        &self,
        engine: &mut Engine,
        zone: &str,
        report: &mut ZoneReport,
    ) -> Result<bool, DeviceError> {
        let mut conflicts = 0;
        for _ in 0..MAX_BATCHES {
            let Some(upload) = engine.build_upload(zone).map_err(engine_error)? else {
                return Ok(false);
            };
            let response = self
                .authed_raw(
                    Method::Post,
                    &format!("/v1/zones/{}/changes", segment(zone)),
                    Some(json(&upload)?),
                )
                .await?;
            if is_ok(&response) {
                let result: wire::UploadResult = parse(&response.body)?;
                report.pushed += result.records.len();
                engine
                    .upload_succeeded(zone, &result)
                    .map_err(engine_error)?;
                continue;
            }
            // Records changed on the server: merge what came and go again.
            if response.status == 409
                && let Ok(conflict) = serde_json::from_slice::<wire::RecordChanged>(&response.body)
                && conflict.code == "record_changed"
            {
                let applied = engine
                    .upload_conflicted(zone, &conflict, self.now_millis())
                    .map_err(engine_error)?;
                merge(&mut report.applied, applied);
                conflicts += 1;
                // Something keeps changing the same records: stop. Everything stays staged and
                // the next pass tries again.
                if conflicts >= MAX_CONFLICT_ROUNDS {
                    return Err(DeviceError::Server {
                        status: 409,
                        code: "record_changed".to_owned(),
                    });
                }
                continue;
            }
            if response.status == 410 {
                engine.token_expired(zone).map_err(engine_error)?;
                return Ok(true);
            }
            let error = failure(&response);
            // The batch in flight is cleared, but its records stay dirty: the next pass builds the
            // same batch and gets `TooLarge` again until the host makes a record smaller or
            // deletes it. The error is how the host learns of it.
            if error == DeviceError::TooLarge {
                engine.abandon_upload(zone).map_err(engine_error)?;
            }
            if response.status == 404 {
                return Err(DeviceError::Server {
                    status: 404,
                    code: "zone_not_found".to_owned(),
                });
            }
            return Err(error);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{SyncState, SyncStatus};

    #[test]
    fn path_segments_are_percent_encoded_and_plain_names_are_not() {
        assert_eq!(segment("engineering.settings"), "engineering.settings");
        assert_eq!(segment("list:3f2c"), "list%3A3f2c");
        assert_eq!(segment("a b/c?d#e%"), "a%20b%2Fc%3Fd%23e%25");
        assert_eq!(segment("t0ken-_~."), "t0ken-_~.");
    }

    #[test]
    fn each_error_puts_the_status_in_the_state_the_host_acts_on() {
        let start = SyncStatus {
            state: SyncState::Syncing,
            last_synced: Some(5),
            last_error: None,
        };
        for (error, state) in [
            (DeviceError::Transport, SyncState::Offline),
            (DeviceError::NotSignedIn, SyncState::SignedOut),
            (
                DeviceError::ReauthenticationRequired,
                SyncState::ReauthenticationRequired,
            ),
            (DeviceError::SessionExpired, SyncState::SessionExpired),
            (DeviceError::AccountGone, SyncState::AccountGone),
            (DeviceError::TooLarge, SyncState::Failed),
        ] {
            let after = start.after(&error, 9);
            assert_eq!(after.state, state, "{error:?}");
            assert_eq!(
                after.last_synced,
                Some(5),
                "a failure keeps the last good time"
            );
            assert!(after.last_error.is_some());
        }
    }
}
