//! Typed errors. None carries a password, a token, a code, a key or a URL.

use std::time::Duration;

/// The key store failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the key store failed")]
pub struct StoreError;

/// Why a call failed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    /// The network failed or timed out. Nothing is known about whether the server acted.
    #[error("the network failed")]
    Transport,
    /// The session's password sign-in is older than ten minutes: call
    /// [`crate::DeviceClient::reauthenticate`] and send the same request again.
    #[error("sign in again to do this")]
    ReauthenticationRequired,
    /// The emailed code, a second-factor code or the approval digits are wrong or have expired.
    #[error("the code is wrong or has expired")]
    InvalidCode,
    /// Too many attempts; try again after `retry_after` when the server said when.
    #[error("too many attempts")]
    RateLimited { retry_after: Option<Duration> },
    /// The account's deletion is scheduled; changes that could lock the owner out wait.
    #[error("the account is scheduled for deletion")]
    DeletionScheduled,
    /// The account was deleted. This device's data on the server is gone.
    #[error("this account was deleted")]
    AccountGone,
    /// A value, a record or an upload is over a limit.
    #[error("too large")]
    TooLarge,
    /// The email or the password is wrong (the server cannot tell which).
    #[error("the email or password is wrong")]
    LoginFailed,
    /// The invite is unknown, used, expired or missing.
    #[error("the invite is not valid")]
    InviteInvalid,
    /// The second-factor code or recovery code was refused.
    #[error("the second-factor code was refused")]
    SecondFactorFailed,
    /// There is no signed-in identity in the key store.
    #[error("not signed in")]
    NotSignedIn,
    /// The key store already holds a device. Sign out, forgetting it, before signing in as another.
    #[error("this device already belongs to an account")]
    StoreNotEmpty,
    /// The session is expired or was signed out elsewhere, and the account still exists.
    #[error("the session ended; sign in again")]
    SessionExpired,
    /// Only a trusted device can do this.
    #[error("this device is not trusted yet")]
    DeviceNotTrusted,
    /// A value the caller gave is not valid (an email, an address, a name).
    #[error("{0}")]
    InvalidInput(&'static str),
    /// The approval ended: ten minutes passed, or either device cancelled or answered wrongly.
    /// Start a new one.
    #[error("the approval ended")]
    ApprovalExpired,
    /// The other device has not done its step yet; ask again shortly.
    #[error("the other device has not answered yet")]
    ApprovalNotReady,
    /// The two devices did not agree, or the server showed this device something other than what
    /// the approval was made with. The approval is cancelled; start a new one.
    #[error("the approval did not match")]
    ApprovalMismatch,
    /// The last trusted device cannot be removed.
    #[error("this is the account's last trusted device")]
    LastTrustedDevice,
    /// The zone was deleted, here or on another device.
    #[error("the zone was deleted")]
    ZoneDeleted,
    /// This device has no key for the zone yet: another device sends it.
    #[error("this device has no key for the zone yet")]
    NoZoneKey,
    /// The sync engine refused something (a record, a key, a snapshot). The message never holds
    /// record content or keys.
    #[error("sync engine: {0}")]
    Engine(String),
    /// The server answered something this client does not handle.
    #[error("the server answered {status} {code}")]
    Server { status: u16, code: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A cryptographic step failed (random source, key material).
    #[error("a cryptographic step failed")]
    Crypto,
}
