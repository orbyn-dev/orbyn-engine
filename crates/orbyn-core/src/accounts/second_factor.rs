//! TOTP as a second factor: setting it up, turning it off, and the step of a sign-in between the
//! password and the session.
//!
//! - The secret is 20 random bytes made here. It is stored sealed (see `AuthSecrets::seal_totp`),
//!   never in the clear and never logged; the enrolment answer shows it once.
//! - A code is accepted for the current 30-second step and one either side, and only if its step
//!   is newer than the last one accepted for the account, so no code works twice. The check and
//!   the update of that step happen under the account's row lock.
//! - Recovery codes are 50 random bits each, stored as keyed digests, and work once.
//! - Every wrong code, replayed code or used recovery code is the same `SecondFactorFailed`.

use super::totp::{self, RECOVERY_CODES, SECRET_LEN};
use super::{
    AccountError, Accounts, AuditAction, Client, LOGIN_STATE_TTL, NewDevice, NewSession, Platform,
    Result, Session, limits, public_keys,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_auth_client::{TOTP_MANAGE_CONTEXT, totp_manage_message};
use orbyn_crypto::Sealed;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

mod api;

const SECOND_FACTOR_CONTEXT: &str = "orbyn/second-factor-state/v1";
/// Wrong codes one sign-in may try before it is closed.
const MAX_ATTEMPTS: i32 = 5;

/// How far a device's signature may be from the server's clock, in seconds.
pub(super) const PROOF_WINDOW_SECS: i64 = 300;

/// What a device signs to change the second factor (see `orbyn_auth_client::totp_manage_message`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManageProof {
    /// Unix seconds, as the device's clock says.
    pub signed_at: i64,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Manage {
    Enrol,
    Confirm,
    Disable,
}

impl Manage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enrol => "enrol",
            Self::Confirm => "confirm",
            Self::Disable => "disable",
        }
    }
}

/// What enrolment shows, once: the secret for an authenticator app and the link that carries it.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpEnrolment {
    /// Base32, for typing into an app.
    pub secret: String,
    /// `otpauth://totp/...`, for a QR code.
    pub uri: String,
}

impl std::fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpEnrolment(..)")
    }
}

/// What was sent as the second factor: exactly one of a code and a recovery code.
pub(super) enum Factor<'a> {
    Code(&'a str),
    Recovery(&'a str),
}

impl<'a> Factor<'a> {
    pub(super) fn parse(code: Option<&'a str>, recovery_code: Option<&'a str>) -> Result<Self> {
        match (code, recovery_code) {
            (Some(code), None) => Ok(Self::Code(code)),
            (None, Some(recovery)) => Ok(Self::Recovery(recovery)),
            _ => Err(AccountError::InvalidRequest),
        }
    }
}

/// How a factor checked out.
#[derive(PartialEq, Eq)]
pub(super) enum Checked {
    Code,
    Recovery,
    Wrong,
}

fn second_factor_aad(id: Uuid, account_id: Uuid) -> Vec<u8> {
    let mut aad = id.as_bytes().to_vec();
    aad.extend_from_slice(account_id.as_bytes());
    aad
}

impl Accounts {
    /// Whether the account has TOTP turned on.
    pub(super) async fn totp_enabled(&self, account_id: Uuid) -> Result<bool> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(enabled == Some(true))
    }
}

impl Accounts {
    /// Opens a sign-in that is waiting for its second factor: the device, sealed for five minutes.
    pub(super) async fn begin_second_factor(
        &self,
        account_id: Uuid,
        device: &NewDevice,
        name: &str,
    ) -> Result<Uuid> {
        let login_id = Uuid::new_v4();
        let body = serde_json::json!({
            "name": name,
            "platform": device.platform.as_str(),
            "signing": URL_SAFE_NO_PAD.encode(device.keys.signing),
            "agreement": URL_SAFE_NO_PAD.encode(device.keys.agreement),
        });
        let plain = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| AccountError::Internal)?);
        let sealed = self
            .secrets
            .state_key()
            .seal(
                SECOND_FACTOR_CONTEXT,
                &second_factor_aad(login_id, account_id),
                &plain,
            )
            .map_err(|_| AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO second_factor_states (id, account_id, sealed, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(login_id)
        .bind(account_id)
        .bind(sealed.to_bytes())
        .bind(LOGIN_STATE_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(login_id)
    }

    fn open_second_factor_state(
        &self,
        login_id: Uuid,
        account_id: Uuid,
        sealed: &[u8],
    ) -> Result<(NewDevice, String)> {
        let plain = Sealed::from_bytes(sealed)
            .and_then(|sealed| {
                self.secrets.state_key().open(
                    SECOND_FACTOR_CONTEXT,
                    &second_factor_aad(login_id, account_id),
                    &sealed,
                )
            })
            .map(Zeroizing::new)
            .map_err(|_| AccountError::LoginFailed)?;
        let body: serde_json::Value =
            serde_json::from_slice(&plain).map_err(|_| AccountError::Internal)?;
        let field = |name: &str| -> Result<Vec<u8>> {
            URL_SAFE_NO_PAD
                .decode(body[name].as_str().ok_or(AccountError::Internal)?)
                .map_err(|_| AccountError::Internal)
        };
        let name = body["name"]
            .as_str()
            .ok_or(AccountError::Internal)?
            .to_owned();
        let device = NewDevice {
            name: name.clone(),
            platform: Platform::parse(body["platform"].as_str().ok_or(AccountError::Internal)?)?,
            keys: public_keys(&field("signing")?, &field("agreement")?)?,
        };
        Ok((device, name))
    }

    /// Checks a code or a recovery code against the account's TOTP, under the account's row lock,
    /// and records what it used: the code's step, or the recovery code. Never says why a wrong
    /// factor is wrong.
    pub(super) async fn check_factor(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
        factor: &Factor<'_>,
    ) -> Result<Checked> {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT secret, last_step FROM account_totp
             WHERE account_id = $1 AND enabled FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let (sealed, last_step) = row.ok_or(AccountError::TotpNotEnabled)?;
        match factor {
            Factor::Code(code) => {
                let secret = self
                    .secrets
                    .open_totp(account_id, &sealed)
                    .ok_or(AccountError::Internal)?;
                let Some(step) = totp::check(&secret, code, self.now(), last_step) else {
                    return Ok(Checked::Wrong);
                };
                sqlx::query("UPDATE account_totp SET last_step = $2 WHERE account_id = $1")
                    .bind(account_id)
                    .bind(step)
                    .execute(&mut **tx)
                    .await?;
                Ok(Checked::Code)
            }
            Factor::Recovery(text) => {
                let Some(plain) = totp::normalize_recovery_code(text) else {
                    return Ok(Checked::Wrong);
                };
                let used: Option<i32> = sqlx::query_scalar(
                    "UPDATE totp_recovery_codes SET used_at = now()
                     WHERE account_id = $1 AND digest = $2 AND used_at IS NULL RETURNING 1",
                )
                .bind(account_id)
                .bind(self.recovery_digest(account_id, &plain).as_slice())
                .fetch_optional(&mut **tx)
                .await?;
                Ok(if used.is_some() {
                    Checked::Recovery
                } else {
                    Checked::Wrong
                })
            }
        }
    }

    fn recovery_digest(&self, account_id: Uuid, normalized: &str) -> [u8; 32] {
        let mut data = account_id.as_bytes().to_vec();
        data.extend_from_slice(normalized.as_bytes());
        self.secrets.digest("totp-recovery", &data)
    }

    /// Replaces the account's recovery codes with ten new ones, returned in the clear this once.
    async fn new_recovery_codes(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<Vec<String>> {
        sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id = $1")
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
        let mut codes = Vec::with_capacity(RECOVERY_CODES);
        for _ in 0..RECOVERY_CODES {
            let code = totp::new_recovery_code().map_err(|_| AccountError::Internal)?;
            let normalized = totp::normalize_recovery_code(&code).ok_or(AccountError::Internal)?;
            sqlx::query("INSERT INTO totp_recovery_codes (account_id, digest) VALUES ($1, $2)")
                .bind(account_id)
                .bind(self.recovery_digest(account_id, &normalized).as_slice())
                .execute(&mut **tx)
                .await?;
            codes.push(code);
        }
        Ok(codes)
    }

    /// Whether sign-in asks for a second factor, and whether an enrolment waits for its code.
    pub async fn totp_status(&self, account_id: Uuid) -> Result<(bool, bool)> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok((enabled == Some(true), enabled == Some(false)))
    }

    /// The time codes and signatures are judged against: the system clock unless a test set one.
    pub(super) fn now(&self) -> u64 {
        (self.clock.0)()
    }

    /// Counts one sign-in code attempt: against the account from this address (10 in 15 minutes)
    /// and against the account from anywhere (30). The narrower is counted first, so an attempt it
    /// refuses never uses up the wider one, and a refused attempt is not recorded.
    pub(super) async fn allow_sign_in_attempt(
        &self,
        client: &Client,
        account_id: Uuid,
    ) -> Result<()> {
        let pair = self.account_and_address_digest(client, account_id);
        if limits::allow(
            &self.pool,
            "totp-account-ip",
            &pair,
            self.limits.totp_per_account_and_ip,
        )
        .await?
            && limits::allow(
                &self.pool,
                "totp-account",
                &self.account_digest(account_id),
                self.limits.totp_per_account,
            )
            .await?
        {
            Ok(())
        } else {
            Err(AccountError::TooManyAttempts)
        }
    }

    /// A right code gives its attempt back, to both buckets, so the owner's own sign-ins never
    /// use up what only wrong guesses should.
    pub(super) async fn give_back_sign_in_attempt(
        &self,
        client: &Client,
        account_id: Uuid,
    ) -> Result<()> {
        limits::give_back(
            &self.pool,
            "totp-account-ip",
            &self.account_and_address_digest(client, account_id),
        )
        .await?;
        limits::give_back(&self.pool, "totp-account", &self.account_digest(account_id)).await?;
        Ok(())
    }

    fn account_and_address_digest(&self, client: &Client, account_id: Uuid) -> [u8; 32] {
        let mut data = account_id.as_bytes().to_vec();
        data.extend_from_slice(&self.ip_digest(client));
        self.secrets.digest("totp-account-ip", &data)
    }

    /// Checks that `session` is a trusted device and that it signed this change with its own key,
    /// now (within five minutes either side), then counts the change against the device's bucket
    /// of 10 in 15 minutes. The signature comes first: only the holder of the key can use up the
    /// bucket, so a stolen token cannot lock the owner out of managing the factor.
    async fn authorise_manage(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
        action: Manage,
        code: &str,
        proof: Option<&ManageProof>,
    ) -> Result<()> {
        let keys = self.require_trusted(tx, session).await?;
        let proof = proof.ok_or(AccountError::DeviceProofRequired)?;
        let now = i64::try_from(self.now()).unwrap_or(i64::MAX);
        if proof.signed_at.abs_diff(now) > PROOF_WINDOW_SECS as u64 {
            return Err(AccountError::DeviceProofRequired);
        }
        let message = totp_manage_message(
            session.account_id.as_bytes(),
            session.device_id.as_bytes(),
            action.as_str(),
            code,
            proof.signed_at,
        );
        orbyn_crypto::verify(&keys, TOTP_MANAGE_CONTEXT, &message, &proof.signature)
            .map_err(|_| AccountError::DeviceProofRequired)?;
        // Turning the factor off needs the password too: a sign-in in the last ten minutes. This
        // comes before the signature is marked as used, so a refusal for it burns nothing.
        if action == Manage::Disable {
            self.require_recent_sign_in(tx, session).await?;
        }
        // Each signed change is accepted once: its time must be after the last one accepted for
        // this device and action. The mark commits on its own, before the change runs, so even a
        // request whose change then fails (factor not on yet, a wrong code, the limit) cannot be
        // sent again later in its window, when the change would succeed. The caller's transaction
        // has locked no device row, so this does not wait on it.
        let newer: Option<i64> = sqlx::query_scalar(
            "INSERT INTO totp_manage_seen (device_id, action, signed_at) VALUES ($1, $2, $3)
             ON CONFLICT (device_id, action) DO UPDATE SET signed_at = EXCLUDED.signed_at
             WHERE totp_manage_seen.signed_at < EXCLUDED.signed_at
             RETURNING signed_at",
        )
        .bind(session.device_id)
        .bind(action.as_str())
        .bind(proof.signed_at)
        .fetch_optional(&self.pool)
        .await?;
        if newer.is_none() {
            return Err(AccountError::DeviceProofRequired);
        }
        let subject = self
            .secrets
            .digest("totp-manage", session.device_id.as_bytes());
        if limits::allow(
            &self.pool,
            "totp-manage",
            &subject,
            self.limits.totp_manage_per_device,
        )
        .await?
        {
            Ok(())
        } else {
            Err(AccountError::TooManyAttempts)
        }
    }

    pub(super) fn account_digest(&self, account_id: Uuid) -> [u8; 32] {
        self.secrets.digest("totp-account", account_id.as_bytes())
    }
}
