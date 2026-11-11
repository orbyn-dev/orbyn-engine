//! What the sync is doing, for the host to show. A `tokio::sync::watch`: the latest value is
//! always there, and a host that only looks now and then misses nothing it needs.

use crate::error::DeviceError;

/// Where the sync stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Nothing has run yet, or the last pass finished.
    Idle,
    /// A pass is running.
    Syncing,
    /// The last pass could not reach the server. Work is never blocked by this.
    Offline,
    /// There is no session: sign in.
    SignedOut,
    /// A recent sign-in is needed: call `reauthenticate`.
    ReauthenticationRequired,
    /// The session ended (signed out elsewhere); the account is alive.
    SessionExpired,
    /// The account was deleted: this device's data on the server is gone.
    AccountGone,
    /// The last pass failed for another reason (see `last_error`).
    Failed,
}

/// The sync status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    pub state: SyncState,
    /// Unix seconds of the last pass that finished without an error.
    pub last_synced: Option<i64>,
    /// The error text of the last failed pass. Never holds a secret.
    pub last_error: Option<String>,
}

impl SyncStatus {
    pub(crate) fn initial() -> Self {
        Self {
            state: SyncState::Idle,
            last_synced: None,
            last_error: None,
        }
    }

    pub(crate) fn after(&self, error: &DeviceError, _now: i64) -> Self {
        let state = match error {
            DeviceError::Transport => SyncState::Offline,
            DeviceError::NotSignedIn => SyncState::SignedOut,
            DeviceError::ReauthenticationRequired => SyncState::ReauthenticationRequired,
            DeviceError::SessionExpired => SyncState::SessionExpired,
            DeviceError::AccountGone => SyncState::AccountGone,
            _ => SyncState::Failed,
        };
        Self {
            state,
            last_synced: self.last_synced,
            last_error: Some(error.to_string()),
        }
    }
}
