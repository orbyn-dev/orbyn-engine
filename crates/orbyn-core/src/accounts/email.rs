//! Email verification: sign-up makes no account and no session, only a pending sign-up that a
//! code sent to the address turns into one.
//!
//! **The throttle (engine#42).** Nothing here caps mail, starts or rows *per address*, because a
//! cap keyed on an address is a cap a stranger can use up to lock the owner out. Starts are
//! limited per client prefix instead, never per address, and one code path serves every state of
//! an address.
//!
//! - **What is capped, by what key.** A start counts against its IP prefix (an IPv4 /24, an IPv6
//!   /64): up to a free allowance it needs nothing, past it a proof of work (`orbyn_crypto::pow`,
//!   asked for with 428 `proof_required` and solved by the client), past a hard cap it is refused.
//!   Each prefix may hold two live rows per address and the address twenty; a newer row evicts the
//!   oldest, so a start never fails and nobody needs room to be made for them.
//! - **One code per address, derived, not stored.** An address with a live pending sign-up has
//!   one code record: a random salt, an expiry (30 minutes), when it was last mailed and how many
//!   wrong guesses it has had **in its whole life**. The 8-character code is derived from the server
//!   secret, the address and the salt, so it can be mailed again without being kept anywhere.
//! - **Any start or resend re-sends the active code**, at most once a minute per address (the
//!   mail is the same code, so skipping one loses nothing), and **a new code is made only when the
//!   active one has expired or died** (10 wrong guesses in all). The mail is therefore bounded by
//!   the per-prefix limits, and nobody can make a code stop working by asking for another.
//! - **One path for every state.** A free address, a taken one and one with sign-ups pending all
//!   run the same statements in the same order: they differ only in the value of the code (a
//!   decoy label that is never mailed, for a taken address) and in the one message queued (the
//!   code, or the notice "someone tried to sign up with your address"). A refusal by a limit
//!   answers like any other failure, and the answer takes at least a fixed time.
//! - **Guessing** a code is limited to 5 wrong guesses from one IP prefix and 10 from all of them
//!   in the code's life. A wrong guess at a dead code counts and fails like any other.

use super::{
    AccountError, Accounts, AuditAction, Client, DeviceState, NewDevice, NewSession, Result,
    limits, new_account_id, sessions,
};
use crate::mail::{self, Kind, Mail};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

mod verification;

/// How long a pending sign-up and its code live from the moment they were made.
const SIGNUP_MINUTES: i32 = 30;
/// Wrong guesses a code survives, over its whole life.
const MAX_WRONG_PER_CODE: i32 = 10;
/// Live rows one prefix may hold for one address, and the address in all. A newer row evicts the
/// oldest, so a start always succeeds.
const MAX_ROWS_PER_PREFIX: i64 = 2;
const MAX_ROWS_PER_ADDRESS: i64 = 20;
/// How long a proof-of-work challenge is good for: the current ten minutes and the ten before.
const POW_BUCKET_SECS: u64 = 10 * 60;

/// What the address's code record says, read under the address lock.
#[derive(sqlx::FromRow)]
struct CodeRecord {
    salt: Vec<u8>,
    live: bool,
    due: bool,
    spent: bool,
    spent_in_window: i32,
    gap_over: bool,
}

fn random_salt() -> Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| AccountError::Internal)?;
    Ok(bytes)
}

impl Accounts {
    /// The code of an address's code record: 8 symbols of the 30-symbol alphabet of
    /// [`crate::email_code`]. Derived from the server secret, so it can be mailed again without
    /// being stored; `label` separates the code that is mailed from the one a taken address's decoy
    /// compares against, which is never mailed. Uniform over the 30^8 codes by rejection.
    fn signup_code(&self, label: &str, email: &str, salt: &[u8]) -> String {
        let mut counter = 0u32;
        loop {
            let mut data = email.as_bytes().to_vec();
            data.push(0);
            data.extend_from_slice(salt);
            data.extend_from_slice(&counter.to_be_bytes());
            let digest = self.secrets.digest(label, &data);
            // 32 bytes make 8 symbols all but always; when too many are skipped, the next block.
            if let Some(code) = crate::email_code::from_bytes(&digest) {
                return code;
            }
            counter += 1;
        }
    }

    pub(super) fn address_digest(&self, label: &str, email: &str) -> [u8; 32] {
        self.secrets.digest(label, email.as_bytes())
    }

    /// The challenge a client at this prefix must answer for the ten minutes starting at `bucket`.
    fn pow_challenge(&self, prefix: &[u8; 32], bucket: u64) -> [u8; 32] {
        let mut data = prefix.to_vec();
        data.extend_from_slice(&bucket.to_be_bytes());
        self.secrets.digest("signup-pow", &data)
    }

    /// The 428 a client at this prefix is answered while it has no free starts left.
    fn ask(&self, prefix: &[u8; 32]) -> AccountError {
        AccountError::ProofRequired {
            challenge: orbyn_hex(&self.pow_challenge(prefix, self.now() / POW_BUCKET_SECS)),
            bits: self.policy.pow_bits,
        }
    }

    /// Limits a sign-up start by its client prefix alone (see the module docs). Runs before any
    /// transaction opens, takes the same slots for every address, and says nothing about one.
    pub(super) async fn throttle_start(
        &self,
        client: &Client,
        proof: Option<(&str, u32)>,
    ) -> Result<()> {
        self.step("start-throttle");
        let prefix = self.ip_prefix_digest(client);
        let within_free = limits::allow(
            &self.pool,
            "signup-start-free",
            &prefix,
            self.limits.signup_start_free_per_prefix,
        )
        .await?;
        // Past the free starts a proof is needed. It is checked here and spent below, only on a
        // start the hard cap lets through.
        let mut spent_proof: Option<([u8; 32], u32)> = None;
        if !within_free {
            let Some((challenge, nonce)) = proof else {
                return Err(self.ask(&prefix));
            };
            let Some(given) = unhex32(challenge) else {
                return Err(self.ask(&prefix));
            };
            let now_bucket = self.now() / POW_BUCKET_SECS;
            // The current ten minutes or the ten before (a client may be slow, or cross the edge).
            let current: bool = given.ct_eq(&self.pow_challenge(&prefix, now_bucket)).into();
            let before: bool = given
                .ct_eq(&self.pow_challenge(&prefix, now_bucket.saturating_sub(1)))
                .into();
            if !(current || before)
                || !orbyn_crypto::pow::verify(&given, nonce, self.policy.pow_bits)
            {
                return Err(self.ask(&prefix));
            }
            spent_proof = Some((given, nonce));
        }
        // The hard cap first: a proof is spent only on a start that is let through.
        let within_max = limits::allow(
            &self.pool,
            "signup-start-max",
            &prefix,
            self.limits.signup_start_max_per_prefix,
        )
        .await?;
        if !within_max {
            return Err(AccountError::TooManyAttempts);
        }
        if let Some((given, nonce)) = spent_proof {
            // A solution buys one start.
            let mut used = given.to_vec();
            used.extend_from_slice(&nonce.to_be_bytes());
            let fresh = limits::allow(
                &self.pool,
                "signup-pow-used",
                &self.secrets.digest("signup-pow-used", &used),
                limits::Limit::new(1, std::time::Duration::from_secs(2 * POW_BUCKET_SECS)),
            )
            .await?;
            if !fresh {
                // Replayed: this start does not count against the cap either.
                limits::give_back(&self.pool, "signup-start-max", &prefix).await?;
                return Err(self.ask(&prefix));
            }
        }
        Ok(())
    }

    /// Serializes everything that decides who gets an address: starts, the making of its code, and
    /// the verifications that create its account. Held until the transaction ends.
    async fn lock_address(tx: &mut Transaction<'_, Postgres>, email: &str) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(email)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Queues the message that carries `code`. Runs in the caller's transaction, so the code and
    /// its message part together.
    async fn queue_code(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        signup_id: Uuid,
        email: &str,
        code: String,
    ) -> Result<()> {
        let message = Mail {
            kind: Kind::VerifyEmail,
            account: Some(signup_id),
            to: email.to_owned(),
            code: Some(code),
        };
        mail::enqueue(&mut **tx, &self.secrets, &message).await?;
        Ok(())
    }

    /// The one step a start and a resend share, for every address. Under the address lock: finds
    /// the address's live code record, or makes a new one when there is none, it has expired, or it
    /// has had 10 wrong guesses; and queues **one** message when the record is new or the last mail
    /// is a minute old: the code for a free address, the notice for a taken one. Both take the same
    /// statements; only the value queued differs.
    async fn code_step(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        email: &str,
        account: Option<Uuid>,
        for_id: Uuid,
    ) -> Result<()> {
        self.step("code-record");
        let record: Option<CodeRecord> = sqlx::query_as(
            "SELECT salt,
                    expires_at > now() AND wrong_guesses < $2 AS live,
                    mailed_at <= now() - make_interval(secs => $3::float8) AS due,
                    wrong_guesses > 0 AS spent,
                    CASE WHEN spent_window_start > now() - interval '24 hours'
                         THEN spent_count ELSE 0 END AS spent_in_window,
                    (last_spent_at IS NULL
                     OR last_spent_at <= now() - make_interval(secs => $4::float8)) AS gap_over
             FROM signup_codes WHERE email = $1 FOR UPDATE",
        )
        .bind(email)
        .bind(MAX_WRONG_PER_CODE)
        .bind(self.policy.mail_pace.as_secs_f64())
        .bind(self.policy.spent_gap.as_secs_f64())
        .fetch_optional(&mut **tx)
        .await?;
        let (salt, send) = match record {
            // The active code: mailed again if the last mail is old enough.
            Some(r) if r.live => (r.salt, r.due),
            // A code that expired or died. A new one is made only when the last mail is a pace
            // old (so mail stays bounded) and, if the old one was spent by wrong guesses, when the
            // address has not had more than `spent_free` of them replaced in the day or the last
            // replacement is a gap old. Otherwise nothing is made now: the start still works and
            // the next one after the delay makes it. A delay, never a refusal.
            Some(r) => {
                let budget = !r.spent
                    || r.spent_in_window
                        < i32::try_from(self.policy.spent_free).unwrap_or(i32::MAX)
                    || r.gap_over;
                if r.due && budget {
                    let salt = random_salt()?.to_vec();
                    sqlx::query(
                        "UPDATE signup_codes
                         SET salt = $2, expires_at = now() + make_interval(mins => $3),
                             mailed_at = now(), wrong_guesses = 0,
                             spent_count = CASE WHEN $4 THEN $5 + 1 ELSE spent_count END,
                             spent_window_start = CASE
                                 WHEN NOT $4 THEN spent_window_start
                                 WHEN spent_window_start > now() - interval '24 hours'
                                     THEN spent_window_start
                                 ELSE now() END,
                             last_spent_at = CASE WHEN $4 THEN now() ELSE last_spent_at END
                         WHERE email = $1",
                    )
                    .bind(email)
                    .bind(&salt)
                    .bind(SIGNUP_MINUTES)
                    .bind(r.spent)
                    .bind(r.spent_in_window)
                    .execute(&mut **tx)
                    .await?;
                    (salt, true)
                } else {
                    (r.salt, false)
                }
            }
            None => {
                let salt = random_salt()?.to_vec();
                sqlx::query(
                    "INSERT INTO signup_codes (email, salt, expires_at, mailed_at, wrong_guesses)
                     VALUES ($1, $2, now() + make_interval(mins => $3), now(), 0)",
                )
                .bind(email)
                .bind(&salt)
                .bind(SIGNUP_MINUTES)
                .execute(&mut **tx)
                .await?;
                (salt, true)
            }
        };
        self.step("mail");
        if send {
            sqlx::query("UPDATE signup_codes SET mailed_at = now() WHERE email = $1")
                .bind(email)
                .execute(&mut **tx)
                .await?;
            if account.is_some() {
                self.queue_notice(tx, email, account).await?;
            } else {
                let code = self.signup_code("signup-code", email, &salt);
                self.queue_code(tx, for_id, email, code).await?;
            }
        }
        Ok(())
    }

    /// The sign-up id to answer. Whatever the address's state and whatever the limits said, the
    /// caller answers the same: a row is stored (a decoy if the address has an account) and the
    /// address's code is mailed if it is time.
    pub(super) async fn start_signup(
        &self,
        client: &Client,
        email: &str,
        password_file: &[u8],
        device: &NewDevice,
        name: &str,
        invite_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let prefix = self.ip_prefix_digest(client);
        let mut tx = self.pool.begin().await?;
        self.step("lock");
        Self::lock_address(&mut tx, email).await?;
        let account: Option<Uuid> = sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM pending_signups WHERE email = $1 AND expires_at <= now()")
            .bind(email)
            .execute(&mut *tx)
            .await?;
        let id = Uuid::new_v4();
        self.code_step(&mut tx, email, account, id).await?;
        // Room for this row: the newest rows of this prefix, then of the address, stay.
        self.step("evict");
        sqlx::query(
            "DELETE FROM pending_signups WHERE id IN (
                 SELECT id FROM pending_signups WHERE email = $1 AND prefix_digest = $2
                 ORDER BY created_at DESC, id OFFSET $3)",
        )
        .bind(email)
        .bind(prefix.as_slice())
        .bind(MAX_ROWS_PER_PREFIX - 1)
        .execute(&mut *tx)
        .await?;
        // Rows younger than a quarter of an hour are never evicted by the address's cap, so
        // twenty quick starts from other prefixes cannot push out the row of an owner who started
        // a moment ago (the address may hold more than twenty for that long).
        sqlx::query(
            "DELETE FROM pending_signups WHERE id IN (
                 SELECT id FROM pending_signups WHERE email = $1
                 ORDER BY created_at DESC, id OFFSET $2)
             AND created_at < now() - interval '15 minutes'",
        )
        .bind(email)
        .bind(MAX_ROWS_PER_ADDRESS - 1)
        .execute(&mut *tx)
        .await?;
        self.step("insert");
        sqlx::query(
            "INSERT INTO pending_signups
                 (id, email, decoy, password_file, device_name, device_platform,
                  device_signing_key, device_agreement_key, expires_at, invite_id, prefix_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(mins => $9), $10, $11)",
        )
        .bind(id)
        .bind(email)
        .bind(account.is_some())
        .bind(password_file)
        .bind(name)
        .bind(device.platform.as_str())
        .bind(device.keys.signing.as_slice())
        .bind(device.keys.agreement.as_slice())
        .bind(SIGNUP_MINUTES)
        .bind(invite_id)
        .bind(prefix.as_slice())
        .execute(&mut *tx)
        .await?;
        self.step("commit");
        tx.commit().await?;
        Ok(id)
    }
}

fn orbyn_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
