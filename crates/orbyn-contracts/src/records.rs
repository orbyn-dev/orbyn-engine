//! Record reads, uploads and change-page wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A record as the server keeps it. The server never reads the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Record {
    pub record_id: String,
    pub record_type: String,
    /// Assigned by the server; send it back as `expected_version` to replace it.
    #[ts(type = "number")]
    pub version: i64,
    /// Base64url; `None` for a tombstone.
    pub ciphertext: Option<String>,
    /// The record key wrapped with the zone key, base64url; `None` for a tombstone.
    pub wrapped_key: Option<String>,
    pub author_device_id: String,
    /// RFC 3339.
    pub modified_at: String,
    pub deleted: bool,
    /// A tombstone's proof from the device that deleted it, base64url; `None`
    /// for live records and for tombstones left by deleting the zone.
    #[serde(default)]
    #[ts(optional)]
    pub delete_proof: Option<String>,
}

/// One change in an upload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "op", rename_all = "snake_case")]
#[ts(export)]
pub enum RecordChange {
    /// Creates the record (`expected_version: null`) or replaces the version
    /// last seen, a tombstone included.
    Save {
        record_id: String,
        /// 1 to 64 characters.
        record_type: String,
        #[ts(type = "number | null")]
        expected_version: Option<i64>,
        /// Base64url, at most 256 KiB decoded.
        ciphertext: String,
        /// Base64url, at most 1 KiB decoded.
        wrapped_key: String,
    },
    /// Turns the record into a tombstone.
    Delete {
        record_id: String,
        #[ts(type = "number")]
        expected_version: i64,
        /// The deleting device's signature over the delete, base64url, at most
        /// 256 bytes decoded. Stored with the tombstone for other devices to check.
        #[serde(default)]
        #[ts(optional)]
        proof: Option<String>,
    },
}

/// `POST /v1/zones/{zone}/changes`. Applied all or nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UploadChanges {
    /// A UUID the client makes once per batch and reuses on every retry of it.
    pub operation_id: String,
    /// At most 200, each record once.
    pub changes: Vec<RecordChange>,
}

/// A record version an upload wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SavedRecord {
    pub record_id: String,
    pub record_type: String,
    #[ts(type = "number")]
    pub version: i64,
    pub deleted: bool,
}

/// The answer to [`UploadChanges`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UploadResult {
    /// The zone token right after this upload.
    pub token: String,
    /// RFC 3339; the same for every record of the batch.
    pub modified_at: String,
    pub records: Vec<SavedRecord>,
    /// True when the operation id was applied before and this is its first answer.
    pub replayed: bool,
}

/// A record whose server version is not the one the upload expected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecordConflict {
    pub record_id: String,
    /// The server's record, a tombstone included; `None` if it never existed.
    pub server_record: Option<Record>,
}

/// The 409 body of an upload that wrote nothing because records changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecordChanged {
    /// Always `record_changed`.
    pub code: String,
    pub message: String,
    pub conflicts: Vec<RecordConflict>,
}

/// `GET /v1/zones/{zone}/changes?since=<token>&limit=<1-200>`: the latest state
/// of each record changed after the token, oldest change first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ZoneChanges {
    pub records: Vec<Record>,
    /// Pass as `since` next time.
    pub token: String,
    /// More changes wait; fetch again with `token`.
    pub more: bool,
    pub zone_deleted: bool,
}
