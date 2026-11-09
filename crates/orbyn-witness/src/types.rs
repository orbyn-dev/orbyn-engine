//! The witness's public request, pin and configuration types.

use orbyn_translog::{Entry, Hash, Proof, UnsignedHead};

/// The most entries one cosign request may carry; a witness that is behind catches up in chunks.
pub const MAX_ENTRIES: usize = 1000;
/// How far a head's `time_ms` may be from the witness's clock.
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// One entry of a request, with what the witness needs to check its map update: the length of the
/// account's chain before it, and the map path as the map stood before this entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignEntry {
    pub entry: Entry,
    pub chain_len: u64,
    pub path: Proof,
}

/// A request to cosign a head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignRequest {
    pub head: UnsignedHead,
    pub log_signature: [u8; 64],
    pub consistency_proof: Vec<Hash>,
    /// The entries since the witness's last size, in order: exactly `head.size - last size`.
    pub entries: Vec<CosignEntry>,
    /// A head on the way to a later one (a witness catching up through the key service's chain of
    /// heads): its time must not be before the last head's and not ahead of this witness's clock
    /// by more than the skew, but it may be older, since the witness was away. The head that ends
    /// the catch-up (`false`) must be within the skew of the clock either way.
    pub intermediate: bool,
}

/// The head the operator pins to start a witness by replay: **the whole signed head**, as the key
/// service published it. The replay checks the log signature, the size, the log root and both map
/// roots it recomputes against it, and takes the hash and the time from it; nothing in it is
/// trusted unchecked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHead {
    pub head: UnsignedHead,
    pub log_signature: [u8; 64],
}

/// What a witness is set up with.
#[derive(Debug, Clone)]
pub struct Config {
    /// The log keys it accepts, by version.
    pub log_keys: Vec<(u32, [u8; 32])>,
    pub max_entries: usize,
    pub max_skew_ms: u64,
}

impl Config {
    pub fn new(log_keys: Vec<(u32, [u8; 32])>) -> Self {
        Self {
            log_keys,
            max_entries: MAX_ENTRIES,
            max_skew_ms: MAX_SKEW_MS,
        }
    }
}
