//! The witness: it checks each head the key service builds, **including what the two maps say**,
//! and only then cosigns it. The log key signs any head the key service builds, honest or not, so
//! this check is the control.
//!
//! A request carries the new head and its log signature, the proof that the log extends, **the
//! entries since the witness's last size**, and for each entry the map path as its map stood
//! before it. The witness checks the log signature, that the log extends (the consistency proof,
//! and the entries' leaf hashes appended to its own frontier giving the head's root), and that
//! both map roots are exactly what applying those entries to its own roots gives
//! (`orbyn_translog::map::update`), with each entry continuing its account's chain. Its cost is
//! O(k log n) hashes for k entries, and it needs no database.
//!
//! It signs `orbyn/log-cosign/v1 ‖ head hash ‖ its own time`. Freshness is read from that time,
//! never the head's `time_ms`, which the key service writes. A head with the same size and roots
//! as the last is cosigned again with a new time: that is how an idle log stays fresh.
//!
//! **It never trusts a map root an operator supplies.** A new witness starts from the empty map
//! ([`Witness::bootstrap_empty`]) or replays the whole log ([`Witness::bootstrap_replay`]); the
//! state it keeps is written with `fsync` before it answers ([`state`]).

mod clock;
mod reason;
mod state;
mod types;
mod witness;

#[cfg(feature = "test-support")]
pub mod testing;

pub mod client;
pub mod messages;
pub mod service;
pub mod wire;

pub use clock::{Clock, SystemClock};
pub use reason::{CosignError, Held, Reason, Refusal, ReplayCause, StartError};
pub use state::{FileStore, HEAD_LEN, MemoryStore, SignedHead, State, StateStore, StoreError};
pub use types::{Config, CosignEntry, CosignRequest, MAX_ENTRIES, MAX_SKEW_MS, PinnedHead};
pub use witness::Witness;

pub use orbyn_translog::{Cosignature, cosign_message, cosigned_enough, threshold_ok};
