//! Accounts, sessions and trusted devices.
//!
//! - Sign-up and sign-in use OPAQUE (RFC 9807): the server never sees a password
//!   and keeps only the registration record. An unknown email gets a fake
//!   answer built from the server setup, so the answer does not tell whether an
//!   account exists.
//! - The server's half of a sign-in is sealed and kept in Postgres for five
//!   minutes, so any replica can finish it.
//! - A session token is 32 random bytes shown once; only its SHA-256 digest is
//!   stored. It lasts 30 days from its last use and at most one year.
//! - The first device is trusted at sign-up. A device that signs in later is
//!   pending until a trusted device signs its keys and the person types the
//!   six-digit code from the trusted device on it.
//!
//! Every operation checks its own authorization against the database; a route
//! only parses and maps.

mod delete;
mod delete_unused;
mod device_app;
mod devices;
mod email;
pub mod email_code;
pub mod invites;
pub mod limits;
mod login;
mod push_tokens;
mod register;
mod second_factor;
pub mod secrets;
mod service;
mod sessions;
pub mod totp;
/// How long a deleted account's tombstone is kept, in days. A session lasts at most a year, so a
/// device offline for longer would be signed out by expiry anyway.
pub const TOMBSTONE_DAYS: i32 = 400;

pub use delete::{FRESH_SIGN_IN_SECS, signed_in_recently};
pub use delete_unused::{DELETE_UNUSED_TTL, REQUEST_JOB_KIND as DELETE_UNUSED_JOB_KIND};
pub use device_app::App;
pub use limits::{Limit, Limits};
pub use push_tokens::PUSH_TOKEN_DAYS;
pub use second_factor::{ManageProof, TotpEnrolment};
pub use secrets::{AuthSecrets, SecretsError};

use chrono::{DateTime, Utc};
use orbyn_auth_client::opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use orbyn_auth_client::{LOGIN_CONTEXT, OsRng, Suite, normalize_email};
use orbyn_crypto::{DevicePublic, Sealed};
use sqlx::{PgPool, Postgres, Transaction};
use std::net::IpAddr;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

/// How long the server keeps its half of a sign-in.
pub const LOGIN_STATE_TTL: Duration = Duration::from_secs(5 * 60);
const LOGIN_STATE_CONTEXT: &str = "orbyn/login-state/v1";

/// What went wrong. Messages never include emails, tokens or keys.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("the request is not valid")]
    InvalidRequest,
    #[error("the email address is not valid")]
    InvalidEmail,
    #[error("the device name must be 1 to 100 characters")]
    InvalidDeviceName,
    /// A wrong password, an unknown email and an expired sign-in all look alike.
    #[error("the email or password is wrong")]
    LoginFailed,
    #[error("too many attempts; try again later")]
    TooManyAttempts,
    /// This client prefix has used its free sign-up starts: solve `challenge` at `bits` bits
    /// (`orbyn_crypto::pow`) and start again with the nonce.
    #[error("a proof of work is needed to sign up from here")]
    ProofRequired { challenge: String, bits: u32 },
    /// The password was right and the account has a second factor: nothing is signed in yet. Send
    /// the code and this login id to the second-factor step.
    #[error("a second factor is required")]
    SecondFactorRequired { login_id: Uuid },
    /// A wrong code, a code already used and a used recovery code all look alike.
    #[error("the code is wrong")]
    SecondFactorFailed,
    /// A change to the second factor needs a signature from the device's own key; a bearer
    /// token alone is not enough.
    #[error("a signature from this device is needed")]
    DeviceProofRequired,
    /// Deleting an account needs a sign-in from the last ten minutes, so a stolen session cannot
    /// schedule it.
    #[error("sign in again to do this")]
    ReauthenticationRequired,
    /// A deletion is scheduled: changes that could lock the owner out wait until it is cancelled.
    #[error("the account is scheduled for deletion; cancel the deletion first")]
    DeletionScheduled,
    #[error("a second factor is already on for this account")]
    TotpAlreadyEnabled,
    #[error("no second factor is on for this account")]
    TotpNotEnabled,
    /// The pending secret is more than ten minutes old: start again. Answered before the code is
    /// looked at, so a code is never compared against an old secret.
    #[error("the second-factor setup expired; start again")]
    TotpSetupExpired,
    /// A wrong, expired or closed verification code look alike.
    #[error("the code is wrong or has expired; ask for a new one")]
    InvalidEmailCode,
    /// An unknown, expired, used or revoked invite, and one with too many sign-ups waiting, look
    /// alike: one answer, whatever the reason.
    #[error("this invite code can't be used")]
    InviteInvalid,
    /// A wrong, used, voided or expired cancel link token look alike.
    #[error("the cancel link is not valid")]
    InvalidCancelToken,
    /// A wrong, used, voided or expired delete-unused token look alike.
    #[error("the link is not valid")]
    InvalidDeleteUnusedToken,
    /// The token is right, but the account is no longer empty (or a deletion is scheduled).
    #[error("the account is not unused any more")]
    DeleteUnusedNotPossible,
    #[error("the session is not valid")]
    Unauthorized,
    #[error("only a trusted device can do this")]
    DeviceNotTrusted,
    #[error("there is no such item")]
    NotFound,
    #[error("the signature does not match")]
    InvalidSignature,
    #[error("the code is wrong")]
    WrongCode { remaining: i32 },
    #[error("the approval has expired, was cancelled or was used")]
    ApprovalExpired,
    #[error("this approval step needs the one before it, and each step happens once")]
    ApprovalOutOfOrder,
    #[error("the approving device has not confirmed the codes yet")]
    ApprovalNotConfirmed,
    #[error("the revealed nonce does not match the commitment")]
    InvalidCommitment,
    #[error("these keys belong to another device of the account")]
    DeviceKeyConflict,
    #[error("the last trusted device cannot be removed")]
    LastTrustedDevice,
    #[error("the database failed")]
    Database(#[from] sqlx::Error),
    #[error("an internal step failed")]
    Internal,
}

pub type Result<T, E = AccountError> = std::result::Result<T, E>;

/// Where a device runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Web,
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

/// A trusted device's signature over a sign-in start; see
/// `orbyn_auth_client::trusted_start_message`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedStart {
    pub signing_key: [u8; 32],
    pub signed_at: i64,
    pub signature: [u8; 64],
}

/// How far a trusted start's time may be from the server's clock.
const TRUSTED_START_WINDOW_SECS: i64 = 300;

/// A new account's id: 16 bytes from the operating system's CSPRNG, as a version-4 UUID. It takes
/// no argument, so it cannot be derived from an email or anything else; the id of one account
/// says nothing about another, and cannot be guessed. The id is public to anyone who knows the
/// account's service public key (it is named in the certification in the key service's log), and
/// the tombstone status endpoint takes one, which is why it must stay unguessable.
pub(crate) fn new_account_id() -> Result<Uuid> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AccountError::Internal)?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A sign-in state as read back: account, email digest, whether the start was trusted, sealed state.
type LoginStateRow = (Option<Uuid>, Vec<u8>, bool, Vec<u8>, Option<Vec<u8>>);

/// The most devices an account may have waiting for approval at once.
const MAX_PENDING_DEVICES: i64 = 20;

/// The sealed sign-in state is bound to its id and to the account it was made
/// for, so moving it to another account's row makes it fail to open.
fn login_state_aad(login_id: Uuid, account_id: Option<Uuid>) -> Vec<u8> {
    let mut aad = login_id.as_bytes().to_vec();
    match account_id {
        Some(id) => {
            aad.push(1);
            aad.extend_from_slice(id.as_bytes());
        }
        None => aad.push(0),
    }
    aad
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "web" => Self::Web,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            "linux" => Self::Linux,
            _ => return Err(AccountError::Internal),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    Pending,
    Trusted,
}

impl DeviceState {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "pending" => Ok(Self::Pending),
            "trusted" => Ok(Self::Trusted),
            _ => Err(AccountError::Unauthorized),
        }
    }
}

/// A device introducing itself at sign-up or sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDevice {
    pub name: String,
    pub platform: Platform,
    pub app: Option<App>,
    pub keys: DevicePublic,
}

impl NewDevice {
    fn checked_name(&self) -> Result<String> {
        let name = self.name.trim();
        let length = name.chars().count();
        if !(1..=100).contains(&length) || name.chars().any(char::is_control) {
            return Err(AccountError::InvalidDeviceName);
        }
        Ok(name.to_owned())
    }
}

/// Who is asking, for rate limits and the audit log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Client {
    pub ip: Option<IpAddr>,
}

/// A session just issued. The token is never stored and never shown again.
#[derive(Clone, PartialEq, Eq)]
pub struct NewSession {
    pub token: String,
    pub session_id: Uuid,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub device_state: DeviceState,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for NewSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSession")
            .field("token", &"(hidden)")
            .field("session_id", &self.session_id)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("device_state", &self.device_state)
            .finish()
    }
}

/// A valid session, from [`Accounts::authenticate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub device_state: DeviceState,
}

/// The server's answer to a sign-in start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginChallenge {
    pub login_id: Uuid,
    pub response: Vec<u8>,
}

/// A device of the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
    pub platform: Platform,
    pub app: Option<App>,
    pub state: DeviceState,
    pub keys: DevicePublic,
    pub created_at: DateTime<Utc>,
    pub approved_by: Option<Uuid>,
    pub approval_signature: Option<[u8; 64]>,
    /// The approval that trusted this device and the time its approver
    /// signed into it, both part of the signed message.
    pub approval_id: Option<Uuid>,
    pub approval_created_at: Option<i64>,
    /// The SHA-256 of the endorsement that approval carried, covered by the approver's v2
    /// signature; `None` for an approval made before that existed, or without an endorsement.
    pub approval_endorsement_hash: Option<[u8; 32]>,
}

/// An approval just opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Approval {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// A removed device and the signed record of who removed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    pub device_id: Uuid,
    pub keys: DevicePublic,
    pub removed_by: Uuid,
    pub sequence: u64,
    pub signature: [u8; 64],
}

/// An approval as either of its devices sees it. Each later field is set by
/// one step, in order: the commitment, the new device's nonce, the approver's
/// nonce, then the approver's signature and endorsement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalView {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: i64,
    pub approver_id: Uuid,
    pub approver_keys: DevicePublic,
    pub device_id: Uuid,
    pub device_keys: DevicePublic,
    pub commitment: [u8; 32],
    pub device_nonce: Option<[u8; 32]>,
    pub approver_nonce: Option<[u8; 32]>,
    pub signature: Option<[u8; 64]>,
    pub endorsement: Option<Vec<u8>>,
}

/// What the audit log records. Never emails, tokens or keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditAction {
    AccountRegistered,
    LoginSucceeded,
    LoginFailed,
    SessionRevoked,
    SessionsRevokedAll,
    ApprovalCreated,
    ApprovalCodeWrong,
    DeviceApproved,
    DeviceRemoved,
    TotpEnrolled,
    TotpDisabled,
    TotpPassed,
    TotpFailed,
    TotpRecoveryUsed,
    EmailVerified,
    AccountDeletionScheduled,
    AccountDeletionCancelled,
    AccountDeleted,
    AccountDeleteUnusedConfirmed,
    DevicePushRegistered,
    DevicePushRemoved,
}

impl AuditAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::AccountRegistered => "account.registered",
            Self::LoginSucceeded => "login.succeeded",
            Self::LoginFailed => "login.failed",
            Self::SessionRevoked => "session.revoked",
            Self::SessionsRevokedAll => "session.revoked_all",
            Self::ApprovalCreated => "device.approval_created",
            Self::ApprovalCodeWrong => "device.approval_code_wrong",
            Self::DeviceApproved => "device.approved",
            Self::DeviceRemoved => "device.removed",
            Self::TotpEnrolled => "totp.enrolled",
            Self::TotpDisabled => "totp.disabled",
            Self::TotpPassed => "totp.passed",
            Self::TotpFailed => "totp.failed",
            Self::TotpRecoveryUsed => "totp.recovery_used",
            Self::EmailVerified => "account.email_verified",
            Self::AccountDeletionScheduled => "account.deletion_scheduled",
            Self::AccountDeletionCancelled => "account.deletion_cancelled",
            Self::AccountDeleted => "account.deleted",
            Self::AccountDeleteUnusedConfirmed => "account.delete_unused_confirmed",
            Self::DevicePushRegistered => "device.push_registered",
            Self::DevicePushRemoved => "device.push_removed",
        }
    }
}

/// The account service. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Accounts {
    pool: PgPool,
    secrets: Arc<AuthSecrets>,
    limits: Limits,
    clock: Clock,
    /// Where the steps of the email verification paths are recorded, for a test that checks a
    /// real sign-up and a decoy take the same ones. `None` in production.
    trace: Option<Arc<std::sync::Mutex<Vec<&'static str>>>>,
    /// Where the account site is served, for the cancel link in the deletion email.
    account_url: Option<String>,
    /// Whether sign-up needs an invite. **`Invite` unless set**, so a service built without the
    /// mode fails closed; the server sets it from `ORBYN_SIGNUP` (also `invite` by default), and a
    /// test that signs people up asks for `Open`.
    signup: crate::SignupMode,
    /// The sign-up pacing (see [`SignupPolicy`]).
    policy: SignupPolicy,
}

/// The knobs of the sign-up throttle that are times and costs, not counts (those are in
/// [`Limits`]). The defaults are the production ones; a test sets its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignupPolicy {
    /// The shortest time between two mails about one address from starts and resends. The mail is
    /// the same code (or the notice), so a start inside it loses the owner nothing.
    pub mail_pace: Duration,
    /// Every sign-up start, resend and verification takes at least this long to answer, so the time
    /// does not tell an address's state.
    pub response_floor: Duration,
    /// Leading zero bits of the proof of work asked past the free allowance of starts.
    pub pow_bits: u32,
    /// How many spent codes (a code with a wrong guess against it that died or expired) an
    /// address may have replaced at once in a day. After that a spent code is replaced one at a
    /// time, `spent_gap` apart. This is what bounds guessing at an address, whatever number of IP
    /// prefixes the guesses come from; the price is that, while someone keeps spending an
    /// address's codes, its owner waits for the next one.
    pub spent_free: u32,
    pub spent_gap: Duration,
}

impl Default for SignupPolicy {
    fn default() -> Self {
        Self {
            mail_pace: Duration::from_secs(60),
            response_floor: Duration::from_millis(250),
            pow_bits: 18,
            spent_free: 3,
            spent_gap: Duration::from_secs(60 * 60),
        }
    }
}

/// The time a TOTP code or a device's signature is judged against, in Unix seconds. The system
/// clock, unless a test sets one, so a test cannot cross a 30-second step by accident.
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}

fn public_keys(signing: &[u8], agreement: &[u8]) -> Result<DevicePublic> {
    Ok(DevicePublic {
        signing: signing.try_into().map_err(|_| AccountError::Internal)?,
        agreement: agreement.try_into().map_err(|_| AccountError::Internal)?,
    })
}

#[cfg(test)]
mod signup_default_tests {
    use super::*;
    use crate::SignupMode;
    use std::sync::Arc;

    fn secrets() -> AuthSecrets {
        AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("secrets")
    }

    /// A pool that never connects: only the settings of the service are read.
    fn pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .expect("a lazy pool")
    }

    // Sign-up is invite-only unless it is opened on purpose, whichever way the service is built.
    #[tokio::test]
    async fn a_service_made_with_new_is_invite_only() {
        assert_eq!(Accounts::new(pool(), secrets()).signup, SignupMode::Invite);
    }

    #[tokio::test]
    async fn a_service_made_with_shared_secrets_is_invite_only() {
        let service = Accounts::with_shared_secrets(pool(), Arc::new(secrets()));
        assert_eq!(service.signup, SignupMode::Invite);
    }

    #[tokio::test]
    async fn opening_sign_up_is_only_by_asking() {
        let service = Accounts::new(pool(), secrets()).with_signup(SignupMode::Open);
        assert_eq!(service.signup, SignupMode::Open);
    }
}

#[cfg(test)]
mod account_id_tests {
    use super::*;

    #[test]
    fn account_ids_are_random_version_4_uuids_and_never_repeat() {
        let ids: Vec<Uuid> = (0..4096).map(|_| new_account_id().expect("id")).collect();
        for id in &ids {
            assert_eq!(id.get_version_num(), 4);
            assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        }
        let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len(), "no id repeated");
        // Every one of the 122 random bits is set about half the time: nothing constant, no
        // counter, no clock in them. (4096 draws: a bit's count is within 6 standard deviations,
        // 2048 +/- 192, for a fair source; a fixed or time-ordered bit is far outside it.)
        let mut ones = [0u32; 128];
        for id in &ids {
            for (i, byte) in id.as_bytes().iter().enumerate() {
                for bit in 0..8 {
                    ones[i * 8 + bit] += u32::from((byte >> (7 - bit)) & 1);
                }
            }
        }
        for (position, count) in ones.iter().enumerate() {
            // Bits 48..52 are the version and 64..66 the variant.
            if (48..52).contains(&position) || (64..66).contains(&position) {
                continue;
            }
            assert!(
                (1856..=2240).contains(count),
                "bit {position} was set {count} times of 4096"
            );
        }
    }

    /// The id comes from `new_account_id()` and the sign-up path has nothing else to make one
    /// from: the function takes no input, and the one place an account row is inserted binds it.
    #[test]
    fn the_sign_up_binds_a_fresh_random_id_and_derives_none_from_the_address() {
        let source = [
            include_str!("email.rs"),
            include_str!("email/verification.rs"),
        ]
        .concat();
        assert!(
            source.contains(".bind(new_account_id()?)"),
            "the account row's id is new_account_id()"
        );
        for derived in [
            "Uuid::new_v5",
            "Uuid::new_v3",
            "Uuid::from_bytes(",
            "Uuid::from_u128",
            "Uuid::now_v7",
            "Uuid::new_v7",
        ] {
            assert!(
                !source.contains(derived),
                "sign-up must not make an id with {derived}"
            );
        }
    }
}
