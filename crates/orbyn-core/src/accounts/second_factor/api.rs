//! Public TOTP management and second-factor sign-in entry points.

use super::*;

impl Accounts {
    /// Starts enrolment: a new secret, held pending until `totp_confirm`. Starting again replaces
    /// a pending secret. Trusted device only. An account that already has TOTP on must turn it
    /// off first.
    pub async fn totp_enrol(
        &self,
        session: &Session,
        proof: Option<&ManageProof>,
    ) -> Result<TotpEnrolment> {
        let mut tx = self.pool.begin().await?;
        self.authorise_manage(&mut tx, session, Manage::Enrol, "", proof)
            .await?;
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        let (email,): (String,) = sqlx::query_as("SELECT email FROM accounts WHERE id = $1")
            .bind(session.account_id)
            .fetch_one(&mut *tx)
            .await?;
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1 FOR UPDATE")
                .bind(session.account_id)
                .fetch_optional(&mut *tx)
                .await?;
        if enabled == Some(true) {
            return Err(AccountError::TotpAlreadyEnabled);
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::fill(secret.as_mut()).map_err(|_| AccountError::Internal)?;
        let sealed = self
            .secrets
            .seal_totp(session.account_id, secret.as_slice())
            .ok_or(AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO account_totp (account_id, secret) VALUES ($1, $2)
             ON CONFLICT (account_id) DO UPDATE
             SET secret = EXCLUDED.secret, last_step = 0, created_at = now()",
        )
        .bind(session.account_id)
        .bind(&sealed)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let secret = totp::base32(secret.as_slice());
        Ok(TotpEnrolment {
            uri: totp::otpauth_uri(&email, &secret),
            secret,
        })
    }

    /// Turns TOTP on with a current code from the pending secret, and returns the one-time
    /// recovery codes. They are shown now and never again; any earlier ones are replaced.
    pub async fn totp_confirm(
        &self,
        client: &Client,
        session: &Session,
        code: &str,
        proof: Option<&ManageProof>,
    ) -> Result<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        self.authorise_manage(&mut tx, session, Manage::Confirm, code, proof)
            .await?;
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        let pending: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT secret, last_step FROM account_totp
             WHERE account_id = $1 AND NOT enabled FOR UPDATE",
        )
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (sealed, last_step) = pending.ok_or(AccountError::InvalidRequest)?;
        let secret = self
            .secrets
            .open_totp(session.account_id, &sealed)
            .ok_or(AccountError::Internal)?;
        let Some(step) = totp::check(&secret, code, self.now(), last_step) else {
            drop(tx);
            self.audit(
                &self.pool,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::TotpFailed,
            )
            .await?;
            return Err(AccountError::SecondFactorFailed);
        };
        let codes = self.new_recovery_codes(&mut tx, session.account_id).await?;
        sqlx::query(
            "UPDATE account_totp SET enabled = true, enabled_at = now(), last_step = $2
             WHERE account_id = $1",
        )
        .bind(session.account_id)
        .bind(step)
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::TotpEnrolled,
        )
        .await?;
        tx.commit().await?;
        Ok(codes)
    }

    /// Turns TOTP off. Trusted device only, with its signature and no code: a device that holds
    /// its key is the person's, and a lost authenticator must not stop them. The session must have
    /// finished its sign-in in the last ten minutes (`reauthentication_required`): the key alone
    /// is not enough. Any sign-in waiting
    /// for its second factor is closed.
    pub async fn totp_disable(
        &self,
        client: &Client,
        session: &Session,
        proof: Option<&ManageProof>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.authorise_manage(&mut tx, session, Manage::Disable, "", proof)
            .await?;
        // The account first, shared: a deletion being scheduled holds it exclusively, so either
        // this sees the schedule and refuses, or the schedule waits for this to finish.
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        // Locks in the order a sign-in takes them (its state, then the account's TOTP row), so a
        // disable and a second-factor attempt can never wait for each other.
        sqlx::query("SELECT id FROM second_factor_states WHERE account_id = $1 FOR UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1 FOR UPDATE")
                .bind(session.account_id)
                .fetch_optional(&mut *tx)
                .await?;
        if enabled != Some(true) {
            return Err(AccountError::TotpNotEnabled);
        }
        sqlx::query("DELETE FROM account_totp WHERE account_id = $1")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id = $1")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM second_factor_states WHERE account_id = $1")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::TotpDisabled,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Finishes a sign-in that is waiting for its second factor. The login id comes from
    /// `SecondFactorRequired`; five wrong codes or five minutes close it (`LoginFailed`). On
    /// success the device is added and signed in exactly as it would have been without the factor.
    pub async fn login_second_factor(
        &self,
        client: &Client,
        login_id: Uuid,
        code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<NewSession> {
        let factor = Factor::parse(code, recovery_code)?;
        let waiting: Option<(Uuid,)> = sqlx::query_as(
            "SELECT account_id FROM second_factor_states WHERE id = $1 AND expires_at > now()",
        )
        .bind(login_id)
        .fetch_optional(&self.pool)
        .await?;
        let (account_id,) = waiting.ok_or(AccountError::LoginFailed)?;
        self.allow_sign_in_attempt(client, account_id).await?;

        let mut tx = self.pool.begin().await?;
        Self::lock_account_shared(&mut tx, account_id).await?;
        // The state is read again under its lock: two requests with one login id take turns.
        let state: Option<(Vec<u8>, i32)> = sqlx::query_as(
            "SELECT sealed, attempts FROM second_factor_states
             WHERE id = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(login_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (sealed, attempts) = state.ok_or(AccountError::LoginFailed)?;
        let checked = self.check_factor(&mut tx, account_id, &factor).await?;
        if checked == Checked::Wrong {
            if attempts + 1 >= MAX_ATTEMPTS {
                sqlx::query("DELETE FROM second_factor_states WHERE id = $1")
                    .bind(login_id)
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query(
                    "UPDATE second_factor_states SET attempts = attempts + 1 WHERE id = $1",
                )
                .bind(login_id)
                .execute(&mut *tx)
                .await?;
            }
            self.audit(
                &mut *tx,
                client,
                Some(account_id),
                None,
                AuditAction::TotpFailed,
            )
            .await?;
            tx.commit().await?;
            return Err(AccountError::SecondFactorFailed);
        }
        let (device, name) = self.open_second_factor_state(login_id, account_id, &sealed)?;
        sqlx::query("DELETE FROM second_factor_states WHERE id = $1")
            .bind(login_id)
            .execute(&mut *tx)
            .await?;
        let action = if checked == Checked::Recovery {
            AuditAction::TotpRecoveryUsed
        } else {
            AuditAction::TotpPassed
        };
        self.audit(&mut *tx, client, Some(account_id), None, action)
            .await?;
        tx.commit().await?;
        let session = self
            .complete_login(client, account_id, &device, &name)
            .await?;
        self.give_back_sign_in_attempt(client, account_id).await?;
        Ok(session)
    }
}
