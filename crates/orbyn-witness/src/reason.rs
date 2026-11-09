//! Why a cosign or a start was refused.

use orbyn_translog::Hash;

use crate::state::{SignedHead, StoreError};

/// Why a request was refused. The code is what the key service logs and alerts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The head's time is too far from the witness's clock.
    ClockSkew,
    /// A different head at a size already signed, or a head that does not extend the last one.
    Fork,
    /// A smaller size, or a time before the last head's.
    Rollback,
    /// The log does not extend, or a map path does not prove what it should.
    BadProof,
    /// The map roots are not what the entries give, or an entry breaks its account's chain.
    MapMismatch,
    /// The log signature is not from a pinned log key.
    BadSignature,
    /// The request itself is malformed: the wrong number of entries, or an unreadable entry.
    BadRequest,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Self::ClockSkew => "clock_skew",
            Self::Fork => "fork",
            Self::Rollback => "rollback",
            Self::BadProof => "bad_proof",
            Self::MapMismatch => "map_mismatch",
            Self::BadSignature => "bad_signature",
            Self::BadRequest => "bad_request",
        }
    }
}

/// What a fork or rollback refusal shows: the head the witness holds, so the refusal is evidence
/// and, for a rollback, the place a catch-up that was interrupted resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub size: u64,
    pub log_root: Hash,
    pub service_map_root: Hash,
    pub identity_map_root: Hash,
    pub head_hash: Hash,
    /// The head the witness's chain stands on (not necessarily its last final head), with its log
    /// signature.
    pub head: Option<SignedHead>,
}

/// A refusal: a reason code, a fixed description (never request contents), and for a fork the
/// head held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", reason.code())]
pub struct Refusal {
    pub reason: Reason,
    pub detail: &'static str,
    pub held: Option<Box<Held>>,
}

pub(crate) fn refuse(reason: Reason, detail: &'static str) -> Refusal {
    Refusal {
        reason,
        detail,
        held: None,
    }
}

/// What can stop a cosign: a refusal, or the state not being saved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CosignError {
    #[error(transparent)]
    Refused(#[from] Refusal),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Why a replay did not give the pinned head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayCause {
    /// The number of entries is not the pinned size.
    #[error("its size is not the pinned size")]
    Size,
    /// The entries give another log root than the pinned one.
    #[error("its root is not the pinned root")]
    LogRoot,
    /// The pinned head is not signed by a pinned log key.
    #[error("the pinned head is not signed by a pinned log key")]
    Signature,
    /// The recomputed map roots are not the pinned head's.
    #[error("its map roots are not the pinned head's")]
    MapRoots,
    /// An entry cannot be encoded: the file is damaged.
    #[error("an entry is damaged")]
    Entries,
    /// An entry does not continue its account's chain: the entries are not in order.
    #[error("an entry does not continue its account's chain")]
    Chain,
}

/// What can stop a witness from starting.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StartError {
    #[error(
        "there is no saved state: start with a bootstrap (from the empty log, or replaying it)"
    )]
    NeedsBootstrap,
    #[error("there is saved state already; a bootstrap would replace it")]
    AlreadyStarted,
    #[error("the replayed log is not the pinned head: {0}")]
    Replay(ReplayCause),
    #[error(transparent)]
    Store(#[from] StoreError),
}
