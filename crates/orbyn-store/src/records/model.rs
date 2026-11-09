use crate::{ChangeToken, Record, Result, Saved, StoreError, UploadResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What an applied upload stored for its replays.
#[derive(Serialize, Deserialize)]
pub(super) struct Stored {
    pub(super) seq: i64,
    pub(super) modified_at_micros: i64,
    pub(super) records: Vec<(String, String, i64, bool)>,
}

#[derive(sqlx::FromRow)]
pub(super) struct RecordRow {
    pub(super) record_id: String,
    record_type: String,
    version: i64,
    ciphertext: Option<Vec<u8>>,
    wrapped_key: Option<Vec<u8>>,
    author_device_id: Uuid,
    modified_at: DateTime<Utc>,
    deleted: bool,
    delete_proof: Option<Vec<u8>>,
}

/// A record and the bytes of the page up to and including it.
#[derive(sqlx::FromRow)]
pub(super) struct PageRow {
    #[sqlx(flatten)]
    pub(super) record: RecordRow,
    pub(super) running: i64,
}

pub(super) fn record(row: RecordRow) -> Record {
    Record {
        record_id: row.record_id,
        record_type: row.record_type,
        version: row.version,
        ciphertext: row.ciphertext,
        wrapped_key: row.wrapped_key,
        author_device_id: row.author_device_id,
        modified_at: row.modified_at,
        deleted: row.deleted,
        delete_proof: row.delete_proof,
    }
}

pub(super) fn replay(zone: Uuid, stored: Stored) -> Result<UploadResult> {
    Ok(UploadResult {
        token: ChangeToken::new(zone, stored.seq),
        modified_at: DateTime::from_timestamp_micros(stored.modified_at_micros)
            .ok_or(StoreError::Internal)?,
        records: stored
            .records
            .into_iter()
            .map(|(record_id, record_type, version, deleted)| Saved {
                record_id,
                record_type,
                version,
                deleted,
            })
            .collect(),
        replayed: true,
    })
}

/// Bytes a stored record uses: its ciphertext and wrapped key.
pub(super) fn record_bytes(record: &Record) -> i64 {
    let c = record.ciphertext.as_ref().map_or(0, Vec::len);
    let k = record.wrapped_key.as_ref().map_or(0, Vec::len);
    (c + k) as i64
}
