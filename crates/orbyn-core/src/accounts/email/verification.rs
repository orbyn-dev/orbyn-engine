//! Email verification and resend after the pending sign-up exists.

use super::*;

impl Accounts {
    /// Tells the owner of an address that someone tried to sign up with it, and when. The time and
    /// the sign-in link travel only in the sealed queue entry, like a code, and nothing about who
    /// tried. Without an account URL there is no link, and the email has no button.
    pub(super) async fn queue_notice(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        email: &str,
        account: Option<Uuid>,
    ) -> Result<()> {
        let attempted = chrono::DateTime::from_timestamp(i64::try_from(self.now()).unwrap_or(0), 0)
            .unwrap_or_default();
        let link = self
            .account_url
            .as_ref()
            .map(|url| format!("{url}/sign-in"))
            .unwrap_or_default();
        let message = Mail {
            kind: Kind::SignUpAttempt,
            account,
            to: email.to_owned(),
            code: Some(format!("{}\n{link}", attempted.to_rfc3339())),
        };
        mail::enqueue(&mut **tx, &self.secrets, &message).await?;
        Ok(())
    }

    /// Proves the address with the code sent to it: creates the account for the sign-up named,
    /// from its own password record and device, trusts that device and signs it in, and deletes
    /// every other row of the address. Every failure, for any id, real or decoy, is
    /// `invalid_email_code`: a wrong code, a decoy, a closed or expired sign-up, a dead code and a
    /// refusal by a limit. A real sign-up and a decoy take the same steps.
    pub async fn email_verify(
        &self,
        client: &Client,
        signup_id: Uuid,
        code: &str,
    ) -> Result<NewSession> {
        let started = std::time::Instant::now();
        let result = self.email_verify_inner(client, signup_id, code).await;
        self.pad(started).await;
        result
    }

    async fn email_verify_inner(
        &self,
        client: &Client,
        signup_id: Uuid,
        code: &str,
    ) -> Result<NewSession> {
        // The IP counts every attempt, and a right code gives its slot back.
        self.step("ip-limit");
        let ip = self.ip_digest(client);
        if !limits::allow(
            &self.pool,
            "email-verify-ip",
            &ip,
            self.limits.email_verify_fail_per_ip,
        )
        .await?
        {
            return Err(AccountError::InvalidEmailCode);
        }
        let result = self.verify_attempt(client, signup_id, code).await;
        if result.is_ok() {
            limits::give_back(&self.pool, "email-verify-ip", &ip).await?;
        }
        result
    }

    async fn verify_attempt(
        &self,
        client: &Client,
        signup_id: Uuid,
        code: &str,
    ) -> Result<NewSession> {
        self.step("row-read");
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT email FROM pending_signups WHERE id = $1 AND expires_at > now()",
        )
        .bind(signup_id)
        .fetch_optional(&self.pool)
        .await?;
        let (email,) = row.ok_or(AccountError::InvalidEmailCode)?;
        // The address's code record: a decoy's address has one too.
        self.step("code-read");
        let salt: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT salt FROM signup_codes WHERE email = $1 AND expires_at > now()",
        )
        .bind(&email)
        .fetch_optional(&self.pool)
        .await?;
        let salt = salt.ok_or(AccountError::InvalidEmailCode)?;
        // Guesses from one IP prefix at this code. The code's total is its own counter, below.
        self.step("code-limits");
        let prefix_subject = {
            let mut data = salt.clone();
            data.extend_from_slice(&self.ip_prefix_digest(client));
            self.secrets.digest("email-code-guess-prefix", &data)
        };
        let by_prefix = limits::allow(
            &self.pool,
            "email-code-guess-prefix",
            &prefix_subject,
            self.limits.email_code_guess_per_prefix,
        )
        .await?;
        if !by_prefix {
            return Err(AccountError::InvalidEmailCode);
        }
        let session = self.verify_locked(client, signup_id, &email, code).await?;
        limits::give_back(&self.pool, "email-code-guess-prefix", &prefix_subject).await?;
        Ok(session)
    }

    async fn verify_locked(
        &self,
        client: &Client,
        signup_id: Uuid,
        email: &str,
        code: &str,
    ) -> Result<NewSession> {
        let mut tx = self.pool.begin().await?;
        self.step("lock");
        Self::lock_address(&mut tx, email).await?;
        type Row = (
            String,
            bool,
            Vec<u8>,
            String,
            String,
            Vec<u8>,
            Vec<u8>,
            Option<Uuid>,
        );
        // Read again under the row's lock: two verifications of one sign-up take turns, and the
        // second finds it gone.
        self.step("row-lock");
        let row: Option<Row> = sqlx::query_as(
            "SELECT email, decoy, password_file, device_name, device_platform,
                    device_signing_key, device_agreement_key, invite_id
             FROM pending_signups WHERE id = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(signup_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (email, decoy, password_file, name, platform, signing, agreement, invite_id) =
            row.ok_or(AccountError::InvalidEmailCode)?;
        self.step("code-lock");
        let record: Option<(Vec<u8>, i32)> = sqlx::query_as(
            "SELECT salt, wrong_guesses FROM signup_codes
             WHERE email = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await?;
        let (salt, wrong) = record.ok_or(AccountError::InvalidEmailCode)?;
        let code = crate::email_code::normalise(code);
        self.step("compare");
        // A decoy compares against a code that was never mailed; a dead code (10 wrong guesses
        // in its life) matches nothing. All three take this same comparison.
        let label = if decoy {
            "signup-decoy-code"
        } else {
            "signup-code"
        };
        let matches: bool = self
            .signup_code(label, &email, &salt)
            .as_bytes()
            .ct_eq(code.as_bytes())
            .into();
        let right = matches && !decoy && wrong < MAX_WRONG_PER_CODE;
        if !right {
            self.step("update");
            sqlx::query(
                "UPDATE signup_codes SET wrong_guesses = wrong_guesses + 1 WHERE email = $1",
            )
            .bind(&email)
            .execute(&mut *tx)
            .await?;
            self.step("commit");
            tx.commit().await?;
            return Err(AccountError::InvalidEmailCode);
        }
        sqlx::query("DELETE FROM signup_codes WHERE email = $1")
            .bind(&email)
            .execute(&mut *tx)
            .await?;
        // The first verified sign-up wins, and only the one named: the address's other rows go.
        sqlx::query("DELETE FROM pending_signups WHERE email = $1")
            .bind(&email)
            .execute(&mut *tx)
            .await?;
        let account_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO accounts (id, email, password_file, email_verified_at)
             VALUES ($1, $2, $3, now()) ON CONFLICT (email) DO NOTHING RETURNING id",
        )
        .bind(new_account_id()?)
        .bind(&email)
        .bind(&password_file)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(account_id) = account_id else {
            // The address got an account some other way since: this sign-up is moot.
            tx.commit().await?;
            return Err(AccountError::InvalidEmailCode);
        };
        // The invite is used up in the transaction that makes the account: the first sign-up
        // verified with it wins, and a revoked, expired or already used invite makes no account.
        // (Dropping the transaction undoes the account and the deletion of the other rows.)
        if self.signup == crate::SignupMode::Invite {
            self.step("invite-use");
            let used = match invite_id {
                Some(invite) => {
                    sqlx::query(
                        "UPDATE invites SET used_at = now(), used_by_account = $2
                         WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()",
                    )
                    .bind(invite)
                    .bind(account_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                }
                // A sign-up started before invites were required has none to use.
                None => 0,
            };
            if used != 1 {
                return Err(AccountError::InviteInvalid);
            }
        }
        let device_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state, approved_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'trusted', now())",
        )
        .bind(device_id)
        .bind(account_id)
        .bind(&name)
        .bind(&platform)
        .bind(&signing)
        .bind(&agreement)
        .execute(&mut *tx)
        .await?;
        let session = sessions::issue(&mut tx, account_id, device_id, DeviceState::Trusted).await?;
        for action in [AuditAction::AccountRegistered, AuditAction::EmailVerified] {
            self.audit(&mut *tx, client, Some(account_id), Some(device_id), action)
                .await?;
        }
        tx.commit().await?;
        Ok(session)
    }

    /// Sends the address's code again for a pending sign-up, at most three an hour per sign-up id.
    /// It is the same step a start takes: the active code is mailed again if the last mail is a
    /// minute old, and a new code is made only if the active one has expired or died; a taken
    /// address gets its notice instead. A real sign-up and a decoy take the same steps and answer
    /// the same; an id nobody made answers the same too.
    pub async fn email_resend(&self, signup_id: Uuid) -> Result<()> {
        let started = std::time::Instant::now();
        let result = self.email_resend_inner(signup_id).await;
        self.pad(started).await;
        result
    }

    async fn email_resend_inner(&self, signup_id: Uuid) -> Result<()> {
        self.step("resend-limit");
        let subject = self.secrets.digest("email-resend", signup_id.as_bytes());
        if !limits::allow(
            &self.pool,
            "email-resend",
            &subject,
            self.limits.email_resend_per_signup,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }
        self.step("row-read");
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT email FROM pending_signups WHERE id = $1 AND expires_at > now()",
        )
        .bind(signup_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((email,)) = row else {
            return Ok(());
        };
        let mut tx = self.pool.begin().await?;
        self.step("lock");
        Self::lock_address(&mut tx, &email).await?;
        self.step("row-lock");
        let live: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM pending_signups WHERE id = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(signup_id)
        .fetch_optional(&mut *tx)
        .await?;
        if live.is_some() {
            let account: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
                    .bind(&email)
                    .fetch_optional(&mut *tx)
                    .await?;
            self.code_step(&mut tx, &email, account, signup_id).await?;
        }
        self.step("commit");
        tx.commit().await?;
        Ok(())
    }
}
