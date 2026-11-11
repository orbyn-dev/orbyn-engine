//! The device sync engine. It does no IO: a host makes the HTTP calls, keeps the
//! [`Snapshot`] and passes in the wall clock, so the same code runs natively and
//! in the browser.
//!
//! Per zone the engine holds the zone keys, the change token, and a cache of
//! records (their merged [`Fields`] and the last server version seen).
//!
//! - **Outgoing.** [`Engine::stage`] merges an edit into the cache and marks the
//!   record dirty. [`Engine::build_upload`] seals up to 200 dirty records into
//!   one atomic upload with expected versions and an operation id; until the
//!   server answers it returns the same batch, so a retry is idempotent.
//!   [`Engine::upload_succeeded`] applies the new versions;
//!   [`Engine::upload_conflicted`] merges each server copy with
//!   `orbyn_sync::merge_remote` and leaves the records dirty for the next batch,
//!   so no local field is lost.
//! - **Incoming.** [`Engine::apply_changes`] opens and merges a page of
//!   changes, moves the token on and returns what changed. A record that does
//!   not open is quarantined, never blocking the zone.
//! - **Trust.** Devices are trusted only through approval signatures this
//!   device checks itself ([`Engine::verify_devices`]); keys go only to them and
//!   are taken only from them. A zone's key changes only through a rotation a
//!   trusted device signed.
//! - **Deletes** are signed by the deleting device and checked before a
//!   tombstone removes anything.

mod apply;
pub mod crypt;
mod described;
mod keys;
mod pairing;
mod planner;
mod protection;
mod service_key;
mod state;
mod trust;
mod upload;

pub use crypt::KeyId;
pub use pairing::{ApproverPairing, DevicePairing, ENDORSEMENT_CONTEXT, MAX_ENDORSED};
pub use planner::{ITEM_TYPE, item_fields, item_from_fields};
pub use protection::{ProtectionFloor, ProtectionHead, ProtectionState, ProtectionStatus};
pub use service_key::{
    LogAnswers, ServiceKeyPins, ServiceKeyRefusal, VerifiedServiceKey, verify_service_key,
};
pub use trust::{Peer, PinnedKeys, uuid_bytes};

// Every type of another Engine crate that appears in this crate's public signatures or fields, so
// a host that depends on this crate alone (the app may not name `orbyn-contracts`, rule D6) can
// name it. They are the same types, not copies. Left out on purpose: the planner's `Item` and
// `ItemError` (planner only), and the request and response bodies this crate never exposes.
pub use orbyn_contracts::{
    ApprovalNonce, ConfirmApproval, CreateApproval, DeleteZone, Device, DeviceApp, DeviceList,
    DevicePlatform, KeyEnvelope, KeyRotation, NewKeyEnvelope, PendingApproval, ProtectionChain,
    ProtectionLevel, ProtectionLink, Record, RecordChanged, RemoveDevice, SetProtection,
    UploadChanges, UploadResult, ZoneChanges, ZoneList,
};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypt::Place;
use orbyn_auth_client as auth;
use orbyn_contracts as wire;
use orbyn_crypto::{CryptoError, SymmetricKey};
pub use orbyn_crypto::{DeviceKeys, DevicePublic};
use orbyn_sync::{Clock, merge, merge_remote};
pub use orbyn_sync::{Fields, Stamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use trust::Trust;

/// Saves and deletes in one upload, as the store accepts.
pub const MAX_BATCH: usize = 200;
/// Record bytes in one upload.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Ciphertext of one record.
pub const MAX_CIPHERTEXT: usize = 256 * 1024;
/// How long a record deleted by another device while it had local edits stays
/// in the trash.
pub const TRASH_MILLIS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The most records a zone keeps in quarantine, and their bytes.
pub const MAX_QUARANTINE: usize = 1000;
pub const MAX_QUARANTINE_BYTES: usize = 16 * 1024 * 1024;

/// Restarts of one refetch before the host is told to stop.
pub const MAX_REFETCH_RESTARTS: u8 = 3;

/// What went wrong. Messages never include record content or keys.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("a record id must be 1 to 128 characters and a type 1 to 64")]
    InvalidRecord,
    #[error("the zone name is not valid")]
    InvalidZone,
    #[error("this device has no key for the zone yet")]
    NoZoneKey,
    #[error("a record is sealed with a zone key this device does not have")]
    MissingZoneKey { zone: String, key_id: String },
    #[error("the data could not be opened or verified: wrong key, signer or changed bytes")]
    Open,
    #[error("a record's contents are not valid")]
    Decode,
    #[error("a record could not be encoded")]
    Encode,
    #[error("a record is larger than the store accepts")]
    RecordTooLarge,
    #[error("the record was deleted")]
    RecordDeleted,
    #[error("there is no upload waiting for an answer")]
    NoUpload,
    #[error("the answer does not match the upload")]
    Mismatch,
    #[error("a key, id or device in the input is not valid")]
    InvalidInput,
    #[error("the system random source failed")]
    Random,
    #[error("the zone expired again before it was fetched from the start; try again later")]
    ExpiredAgain,
    /// The newest protection setting is older than one this device verified or its approver
    /// vouched for.
    #[error("the protection settings are older than ones this device already knows")]
    ProtectionRollback,
    /// A protection setting differs from one this device verified or its approver vouched for at
    /// the same sequence, or does not follow the verified head.
    #[error("the protection settings fork from the ones this device verified")]
    ProtectionFork,
}

impl From<CryptoError> for ClientError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Random => Self::Random,
            CryptoError::InvalidKey => Self::InvalidInput,
            _ => Self::Open,
        }
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn unb64(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| ClientError::InvalidInput)
}

fn key_id_of(text: &str) -> Result<KeyId> {
    unb64(text)?
        .try_into()
        .map_err(|_| ClientError::InvalidInput)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ClientError::Random)?;
    Ok(bytes)
}

/// A random UUID (version 4), for operation ids.
fn uuid_v4() -> Result<String> {
    let mut b: [u8; 16] = random()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn valid_name(text: &str, max: usize) -> bool {
    let n = text.chars().count();
    (1..=max).contains(&n) && !text.chars().any(char::is_control)
}

/// One cached record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Local {
    pub record_type: String,
    /// Empty once deleted locally.
    pub fields: Fields,
    /// The last server version seen; `None` until the server has it.
    pub version: Option<i64>,
    /// The server does not have everything here yet.
    pub dirty: bool,
    /// Deleted on this device; uploads as a signed delete.
    pub deleted: bool,
    /// Counts local changes, so an answer to an older batch does not mark
    /// newer edits as stored.
    #[serde(default)]
    edits: u64,
}

/// A server copy this device could not open or verify yet. It is kept as is
/// and tried again when keys arrive ([`Engine::retry_quarantined`]); until
/// then the record is left out of uploads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quarantined {
    pub record: wire::Record,
    /// `missing_zone_key`, `open_failed` or `invalid_record`.
    pub reason: String,
}

/// A record another device deleted while this device had edits not yet stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Trashed {
    pub record_type: String,
    pub fields: Fields,
    pub deleted_by: String,
    /// This device's clock when the delete arrived; kept for [`TRASH_MILLIS`].
    pub deleted_at_millis: u64,
}

/// An upload sent and not yet answered.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct InFlight {
    upload: wire::UploadChanges,
    /// Each record's edit count when the batch was built.
    edits: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default)]
struct ZoneState {
    /// Never overwritten: a key id, once known, keeps its key.
    keys: BTreeMap<KeyId, SymmetricKey>,
    /// The key new records are sealed with: the first key accepted, then each
    /// accepted rotation from it.
    current: Option<KeyId>,
    /// The signed record of each key that came from a rotation.
    rotations: BTreeMap<KeyId, wire::KeyRotation>,
    token: Option<String>,
    records: BTreeMap<String, Local>,
    in_flight: Option<InFlight>,
    quarantine: BTreeMap<String, Quarantined>,
    trash: BTreeMap<String, Trashed>,
    /// Records this device held at the server's version when the zone expired,
    /// not yet seen again. `None` outside a refetch.
    refetch: Option<BTreeSet<String>>,
    /// Restarts of the running refetch, because the zone expired again.
    refetch_restarts: u8,
}

impl ZoneState {
    fn current_key(&self) -> Option<(KeyId, &SymmetricKey)> {
        let id = self.current?;
        self.keys.get(&id).map(|k| (id, k))
    }

    /// Drops the oldest quarantined records (lowest versions) until the
    /// quarantine fits its limits; returns their ids.
    fn trim_quarantine(&mut self) -> Vec<String> {
        let size = |q: &Quarantined| {
            q.record.ciphertext.as_ref().map_or(0, String::len)
                + q.record.wrapped_key.as_ref().map_or(0, String::len)
        };
        let mut bytes: usize = self.quarantine.values().map(size).sum();
        let mut evicted = Vec::new();
        while self.quarantine.len() > MAX_QUARANTINE || bytes > MAX_QUARANTINE_BYTES {
            let Some(oldest) = self
                .quarantine
                .iter()
                .min_by_key(|(_, q)| q.record.version)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            if let Some(q) = self.quarantine.remove(&oldest) {
                bytes -= size(&q);
            }
            evicted.push(oldest);
        }
        evicted
    }

    /// Follows accepted rotations from the current key as far as they go.
    fn advance(&mut self) {
        let mut steps = 0;
        while let Some(current) = self.current
            && steps <= self.rotations.len()
        {
            let next = self
                .rotations
                .iter()
                .filter(|(id, r)| {
                    key_id_of(&r.previous_key_id).ok() == Some(current)
                        && self.keys.contains_key(*id)
                })
                .map(|(id, _)| *id)
                .min();
            match next {
                Some(next) => self.current = Some(next),
                None => break,
            }
            steps += 1;
        }
    }
}

/// What changed in the cache, for the host to show.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// Records whose fields changed or that are new.
    pub changed: Vec<String>,
    /// Records that are gone.
    pub removed: Vec<String>,
    /// Records removed by another device's delete while they had local edits;
    /// they are in the trash for 30 days.
    pub trashed: Vec<String>,
    /// Records that could not be opened yet.
    pub quarantined: Vec<String>,
    /// Tombstones without a valid signature from a trusted device. They were
    /// ignored; the local copy is uploaded again.
    pub unverified_deletes: Vec<String>,
    /// Quarantined records dropped, oldest first, to keep the quarantine
    /// within [`MAX_QUARANTINE`] records and [`MAX_QUARANTINE_BYTES`].
    pub evicted: Vec<String>,
    /// Fields left out because their stamp was too far ahead of this clock.
    pub rejected: Vec<RejectedFields>,
    /// More changes wait on the server; fetch again with [`Engine::token`].
    pub more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedFields {
    pub record_id: String,
    pub fields: Vec<String>,
}

/// Which zones to fetch, from one page of `GET /v1/zones`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneCheck {
    /// Zones whose token differs from this device's.
    pub stale: Vec<String>,
    /// Pass as `after` to fetch the next page; `None` on the last page.
    pub next: Option<String>,
}

/// The result of [`Engine::accept_envelopes`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    /// Zones that got a new key; call [`Engine::retry_quarantined`] for them.
    pub zones: Vec<String>,
    pub refused: Vec<RefusedEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedEnvelope {
    pub zone: String,
    pub key_id: String,
    pub sender_device_id: String,
    /// `untrusted_sender`, `conflicting_key`, `invalid_rotation` or `invalid`.
    pub reason: String,
}

/// The engine's state for the host to store. It holds zone keys: a host must
/// seal it before it leaves the process (`orbyn-wasm` does). Its `Debug` prints the account, the
/// device and the number of zones, and never a key or a record.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub account_id: String,
    pub device_id: String,
    pub pinned: BTreeMap<String, PinnedKeys>,
    #[serde(default)]
    pub revoked: BTreeMap<String, PinnedKeys>,
    /// The highest removal sequence this device has counted.
    #[serde(default)]
    pub removal_sequence: u64,
    /// The newest protection setting this device verified.
    #[serde(default)]
    pub protection: Option<ProtectionHead>,
    /// An approver's newest setting this device has not seen yet.
    #[serde(default)]
    pub protection_floor: Option<ProtectionFloor>,
    /// Whether something this device trusts vouches for the chain it follows.
    #[serde(default)]
    pub protection_anchored: bool,
    /// Whether the last walk of the chain reached the server's head with nothing stopped.
    #[serde(default)]
    pub protection_complete: bool,
    pub zones: BTreeMap<String, ZoneSnapshot>,
}

/// One zone of a [`Snapshot`]: its keys (base64url), its records and its upload state. Its
/// `Debug` prints counts only, never a key or a record.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ZoneSnapshot {
    /// Key id to key, both base64url.
    pub keys: BTreeMap<String, String>,
    pub current: Option<String>,
    pub rotations: BTreeMap<String, wire::KeyRotation>,
    pub token: Option<String>,
    pub records: BTreeMap<String, Local>,
    pub quarantine: BTreeMap<String, Quarantined>,
    pub trash: BTreeMap<String, Trashed>,
    #[serde(default)]
    in_flight: Option<InFlight>,
    /// Set while the zone is fetched again from the start after
    /// `token_expired`; see [`Engine::token_expired`].
    #[serde(default)]
    refetch: Option<BTreeSet<String>>,
    #[serde(default)]
    refetch_restarts: u8,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("zones", &self.zones.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ZoneSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSnapshot")
            .field("keys", &self.keys.len())
            .field("records", &self.records.len())
            .finish_non_exhaustive()
    }
}

/// One device's sync engine.
pub struct Engine {
    keys: DeviceKeys,
    trust: Trust,
    protection: protection::Protection,
    clock: Clock,
    zones: BTreeMap<String, ZoneState>,
    /// Records whose newest stamp was more than an hour ahead of the clock when
    /// the engine was restored, and so was not allowed to move this device's clock.
    skipped_future_stamps: usize,
}

/// The stamp device number of a device: the first 8 bytes of its signing key.
pub fn stamp_device(public: &DevicePublic) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&public.signing[..8]);
    u64::from_be_bytes(b)
}

enum Copy {
    Never,
    Tombstone { verified: bool, author: String },
    Live(Fields, i64, String),
    Unreadable(wire::Record, &'static str),
}

fn format_uuid(b: &[u8; 16]) -> String {
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_ids_are_version_4_uuids() -> Result<()> {
        let id = uuid_v4()?;
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(uuid_v4()?, id);
        assert_eq!(format_uuid(&uuid_bytes(&id)?), id);
        Ok(())
    }
}
