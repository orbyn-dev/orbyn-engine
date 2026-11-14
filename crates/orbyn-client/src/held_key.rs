//! The service key this engine verified, as the snapshot keeps it. After a restart the engine
//! still holds the key and the log head it checked, so a host that passes no `known_key` or
//! `seen` is not back to trust on first use, and the `KeyChanged` defence is not lost. The
//! snapshot is sealed under the vault key by the host; this holds a public key and log roots, no
//! secret, and its `Debug` prints neither.

use crate::service_key::VerifiedServiceKey;
use crate::{ClientError, Result, b64, unb64};
use orbyn_translog::verify::Seen;
use serde::{Deserialize, Serialize};

/// A verified service key and the head it was checked against, base64url.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldServiceKey {
    identity_version: u32,
    public_key: String,
    statement_hash: String,
    entry_index: u64,
    seen: HeldHead,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeldHead {
    size: u64,
    log_root: String,
    service_map_root: String,
    identity_map_root: String,
    witnessed_ms: u64,
}

impl std::fmt::Debug for HeldServiceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldServiceKey")
            .field("identity_version", &self.identity_version)
            .field("entry_index", &self.entry_index)
            .finish_non_exhaustive()
    }
}

impl From<&VerifiedServiceKey> for HeldServiceKey {
    fn from(key: &VerifiedServiceKey) -> Self {
        Self {
            identity_version: key.identity_version,
            public_key: b64(&key.public_key),
            statement_hash: b64(&key.statement_hash),
            entry_index: key.entry_index,
            seen: HeldHead {
                size: key.seen.size,
                log_root: b64(&key.seen.log_root),
                service_map_root: b64(&key.seen.service_map_root),
                identity_map_root: b64(&key.seen.identity_map_root),
                witnessed_ms: key.seen.witnessed_ms,
            },
        }
    }
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N]> {
    unb64(text)?
        .try_into()
        .map_err(|_| ClientError::InvalidInput)
}

impl HeldServiceKey {
    /// The key as the engine holds it. A field that is not what it should be is
    /// [`ClientError::InvalidInput`]: the snapshot is refused, never read as "no key".
    pub(crate) fn restore(&self) -> Result<VerifiedServiceKey> {
        Ok(VerifiedServiceKey {
            identity_version: self.identity_version,
            public_key: fixed(&self.public_key)?,
            statement_hash: fixed(&self.statement_hash)?,
            entry_index: self.entry_index,
            seen: Seen {
                size: self.seen.size,
                log_root: fixed(&self.seen.log_root)?,
                service_map_root: fixed(&self.seen.service_map_root)?,
                identity_map_root: fixed(&self.seen.identity_map_root)?,
                witnessed_ms: self.seen.witnessed_ms,
            },
        })
    }
}

/// The newer of the head a host passed and the head this engine holds: the larger log wins, and
/// on a tie the held one, so a host can never move the engine to an older head.
pub(crate) fn newer(host: Option<&Seen>, held: Option<&Seen>) -> Option<Seen> {
    match (host, held) {
        (Some(host), Some(held)) if host.size > held.size => Some(*host),
        (_, Some(held)) => Some(*held),
        (Some(host), None) => Some(*host),
        (None, None) => None,
    }
}
