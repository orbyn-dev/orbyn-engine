//! Account, sign-up, sign-in, second-factor and deletion wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Where a device runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DevicePlatform {
    Web,
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

/// Whether a device may use the account. A device that signs in is `pending`
/// until a trusted device approves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DeviceState {
    Pending,
    Trusted,
}

/// A device introducing itself. Keys are base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewDevice {
    /// A name the person chose, 1 to 100 characters.
    pub name: String,
    pub platform: DevicePlatform,
    /// The Ed25519 public key (32 bytes).
    pub signing_key: String,
    /// The X25519 public key (32 bytes).
    pub agreement_key: String,
}

/// `POST /v1/accounts/register/start`. Byte fields are base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RegisterStart {
    pub email: String,
    /// The OPAQUE registration request.
    pub registration_request: String,
}

/// The answer to [`RegisterStart`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RegisterStarted {
    /// The OPAQUE registration response.
    pub registration_response: String,
}

/// `POST /v1/accounts/register/finish`: creates the account with this device trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RegisterFinish {
    pub email: String,
    /// The OPAQUE registration upload.
    pub registration_upload: String,
    pub device: NewDevice,
    /// The device's signature over the `orbyn/device-register/v1` message.
    pub device_signature: String,
    /// The invite code, when the server asks for one (`ORBYN_SIGNUP=invite`, the default). Any
    /// case, with or without dashes and spaces. An unknown, expired, used or revoked code, and a
    /// missing one, are the same answer: 400 `invite_invalid`. Ignored when sign-up is open.
    #[serde(default)]
    #[ts(optional)]
    pub invite: Option<String>,
    /// A proof of work, when the server asked for one (428 `proof_required`, see
    /// [`ProofRequired`]). Sent with the same request again.
    #[serde(default)]
    #[ts(optional)]
    pub proof: Option<SignupProof>,
}

/// The solution to a [`ProofRequired`] challenge: a `nonce` such that
/// `SHA-256("orbyn/signup-pow/v1" || challenge || nonce as 4 bytes big endian)` begins with `bits`
/// zero bits (`orbyn_crypto::pow::solve`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SignupProof {
    /// The challenge as the server sent it, 64 hex digits.
    pub challenge: String,
    pub nonce: u32,
}

/// The body of 428 `proof_required`: this client address has used its free sign-up starts. Solve
/// the challenge and send `register/finish` again with the proof. A solution buys one start and
/// the challenge is good for 10 to 20 minutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProofRequired {
    pub code: String,
    pub message: String,
    pub challenge: String,
    pub bits: u32,
}

/// `POST /v1/invites/check`: whether an invite code could be used to sign up now, before the
/// person goes on. No session. Answers 204, or the same 400 `invite_invalid` as `register/finish`
/// for any code that cannot be used; 10 of those an hour per client address, then 429
/// `too_many_attempts`. It spends nothing and records nothing: `email/verify` is what uses an
/// invite up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct InviteCheck {
    pub invite: String,
}

/// `POST /v1/sessions/login/start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginStart {
    pub email: String,
    /// The OPAQUE credential request.
    pub credential_request: String,
    /// Sent by a device that is already trusted on this account, so its sign-in
    /// is not held back by the per-email limit that slows password guessing.
    #[serde(default)]
    #[ts(optional)]
    pub trusted_device: Option<TrustedDeviceProof>,
}

/// A trusted device's signature over this sign-in start, made with
/// `orbyn_auth_client::trusted_start_message`. Valid for five minutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TrustedDeviceProof {
    /// The device's Ed25519 public key, base64url.
    pub signing_key: String,
    /// Unix seconds when it was signed.
    pub signed_at: i64,
    /// Base64url Ed25519 signature.
    pub signature: String,
}

/// The answer to [`LoginStart`]. It has the same shape whether or not the email
/// has an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginStarted {
    /// Names this sign-in for [`LoginFinish`]; it expires after five minutes.
    pub login_id: String,
    /// The OPAQUE credential response.
    pub credential_response: String,
}

/// `POST /v1/sessions/login/finish`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginFinish {
    pub login_id: String,
    /// The OPAQUE credential finalization.
    pub credential_finalization: String,
    pub device: NewDevice,
    /// The device's signature over the `orbyn/device-login/v1` message.
    pub device_signature: String,
}

/// A new session, from sign-up or sign-in. The token is shown once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SessionCreated {
    /// Send as `Authorization: Bearer <token>`.
    pub token: String,
    pub account_id: String,
    pub device_id: String,
    pub device_state: DeviceState,
    /// RFC 3339. Each use moves it 30 days on, up to one year after sign-in.
    pub expires_at: String,
}

/// The answer to `POST /v1/accounts/register/finish`: no account and no session yet, only the
/// name of a sign-up that waits for the code sent to the address. It has the same shape whether
/// or not the address is already taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SignUpPending {
    pub signup_id: String,
}

/// `POST /v1/accounts/email/verify`: the 8-character code sent to the address (`K7QM-R4TW`: the
/// digits 2 to 9 and the letters A to Z without I, L, O and U). Any case is read, and a hyphen or
/// spaces are ignored, so `k7qmr4tw`, `K7QM-R4TW` and ` k7qm r4tw ` are the same code. A right code
/// creates the account with the signing-up device trusted and answers a [`SessionCreated`]. Ten
/// wrong tries kill the code (5 from one IP prefix; the next start or resend brings a new one
/// within the limits in `docs/architecture.md`); any failure is the one answer
/// `invalid_email_code`. The sign-up and its code live 30 minutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailVerify {
    pub signup_id: String,
    pub code: String,
}

/// `POST /v1/accounts/email/resend`: sends a new code for a pending sign-up, at most three an
/// hour. The answer is 204 whether or not the sign-up exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailResend {
    pub signup_id: String,
}

/// The 401 body of a sign-in whose password was right but whose account has a second factor:
/// no session was issued. Send `login_id` and a code to `POST /v1/sessions/login/second-factor`
/// within five minutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SecondFactorRequired {
    /// Always `second_factor_required`.
    pub code: String,
    pub message: String,
    pub login_id: String,
}

/// `POST /v1/sessions/login/second-factor`: the second step of a sign-in. Exactly one of `code`
/// (six digits from the authenticator app) and `recovery_code` (one-time, `XXXXX-XXXXX`).
/// Answers a [`SessionCreated`]; every wrong code is `second_factor_failed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SecondFactorLogin {
    pub login_id: String,
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

/// `POST /v1/accounts/totp`, from a trusted device: a new secret, pending until confirmed.
/// Shown once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpEnrolment {
    /// Base32, for typing into an authenticator app.
    pub secret: String,
    /// `otpauth://totp/Orbyn:<email>?...`, for a QR code.
    pub uri: String,
}

/// `POST /v1/accounts/totp/confirm`: a current code from the pending secret turns TOTP on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpConfirm {
    pub code: String,
    /// The device's `orbyn/totp-manage/v1` signature over the account, device, action and code.
    #[serde(default)]
    pub device_signature: Option<String>,
    /// Unix seconds, as the device signed them (within five minutes of the server's clock).
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// `POST /v1/accounts/totp`: the trusted device proves the request with its own key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpEnrol {
    #[serde(default)]
    pub device_signature: Option<String>,
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// The answer to a confirmed enrolment: ten one-time recovery codes, shown this once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpConfirmed {
    pub recovery_codes: Vec<String>,
}

/// `POST /v1/accounts/totp/disable`, from a trusted device: its signature alone, no code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpDisable {
    #[serde(default)]
    pub device_signature: Option<String>,
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// `POST /v1/accounts/delete`, from a trusted device: schedules the deletion of the whole account
/// and everything in it, seven days from now (answer 202 [`DeletionScheduled`]). The device signs
/// the request (`orbyn/account-delete/v1`) from a session that signed in in the last ten minutes,
/// and when the account has a second factor exactly one of a current `code` and an unused
/// `recovery_code` is needed as well.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteAccount {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
    #[serde(default)]
    pub device_signature: Option<String>,
    /// Unix seconds, as the device signed them (within five minutes of the server's clock).
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// The answer to `POST /v1/accounts/delete`: when the account will be deleted unless it is
/// cancelled first. Asking again while a deletion is scheduled answers the same time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeletionScheduled {
    /// RFC 3339.
    pub deletes_at: String,
}

/// `POST /v1/accounts/delete/cancel`: cancels a scheduled deletion. A trusted device signs it
/// (`orbyn/account-delete-cancel/v1`); a pending device whose session signed in (password and
/// second factor) in the last ten minutes may too. Answer 204, also when nothing was scheduled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CancelAccountDeletion {
    #[serde(default)]
    pub device_signature: Option<String>,
    /// Unix seconds, as the device signed them (within five minutes of the server's clock).
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// `POST /v1/accounts/delete/cancel-by-mail`: the token from the cancel link in the deletion email.
/// No sign-in; it cancels the scheduled deletion and does nothing else. The planner's page opens
/// from the link, shows a "Cancel deletion" button and posts the token only when it is pressed (a
/// mail scanner that opens the link changes nothing). Answer 204, or 400 `invalid_cancel_token`
/// for any wrong, used, voided or expired token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CancelDeletionByMail {
    pub token: String,
}

/// `POST /v1/accounts/delete-unused`: asks for the link that deletes an unused account (one with
/// no key-holding device and nothing ever stored), so the address can sign up again. No sign-in.
/// Always answers 202 `{}`, whatever the address is (an account or not, unused or not, an address
/// or not), so the answer says nothing about the account; the link is mailed only when the
/// account is unused. 429 `too_many_attempts` only for a flood from one network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteUnusedRequest {
    pub email: String,
}

/// `POST /v1/accounts/delete-unused/confirm`: the token from the link in that email. No sign-in;
/// it deletes the account at once if it is still unused and does nothing else. The planner's page
/// opens from the link and posts the token only when its button is pressed (a mail scanner that
/// opens the link changes nothing). Answer 200 [`DeleteUnusedConfirmed`]; 400
/// `invalid_delete_unused_token` for any wrong, used, voided or expired token; 409
/// `delete_unused_not_possible` when the account holds keys or stored data now (nothing is
/// deleted).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteUnusedConfirm {
    pub token: String,
}

/// The answer to `POST /v1/accounts/delete-unused/confirm`. Only the holder of the deletion token
/// sees it, so it leaks nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteUnusedConfirmed {
    /// True only when this deletion gave an invite back: the account was made from an invite that
    /// had not been released before. False for an account made without one, and for one whose
    /// invite was already released.
    pub invite_released: bool,
}

/// `POST /v1/accounts/status`: has this account been deleted? No session (the device's session
/// went with the account). Answer 200 `AccountStatus` when a tombstone exists, and 404 `not_found`
/// for everything else, so it never says that an account exists. 429 `too_many_attempts` past 60
/// an hour from one network. A device asks once after a 401 and wipes only on a 200.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AccountStatusRequest {
    pub account_id: String,
}

/// The answer for a deleted account: the UTC day it was deleted, as an RFC 3339 date at 00:00 UTC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AccountStatus {
    pub deleted_at: String,
}

/// `PUT /v1/devices/current/push-token`: the push token of the signed-in (trusted) device, so a
/// silent wake-up can reach it. `provider` is `apns` or `fcm` (Web Push is Planned). The token is
/// 1 to 512 printable characters with no space. Answer 204; it replaces the device's token and
/// subscribes the device to every zone. `DELETE` on the same path answers 204 and ends both. The
/// server seals the token and logs it nowhere; a push carries no content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PushTokenRequest {
    pub provider: String,
    pub token: String,
}
