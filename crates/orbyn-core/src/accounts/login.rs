//! Sign-in: the OPAQUE exchange, session creation and trusted-device checks.

use super::*;
use uuid::Uuid;

impl Accounts {
    /// The first sign-in step. Known and unknown emails take the same path: both
    /// count against the same limits, both read the database once, and an
    /// unknown email gets a fake answer of the same shape.
    pub async fn login_start(
        &self,
        client: &Client,
        email: &str,
        request: &[u8],
        trusted: Option<&TrustedStart>,
    ) -> Result<LoginChallenge> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        let email_subject = self.secrets.digest("login-email", email.as_bytes());
        let ip_subject = self.ip_digest(client);
        let mut pair = email_subject.to_vec();
        pair.extend_from_slice(&ip_subject);
        let pair_subject = self.secrets.digest("login-email-ip", &pair);
        // A start signed by a device already trusted on this account skips the
        // per-email limits, so the owner is never locked out by someone else's
        // guessing. An invalid proof is simply ignored: it tells nobody anything.
        let proof = trusted;
        let trusted = match proof {
            Some(proof) => self.is_trusted_start(&email, request, proof).await?,
            None => false,
        };
        // The device that proved itself, so that only it can skip the second factor at the finish.
        let trusted_signer: Option<Vec<u8>> = proof
            .filter(|_| trusted)
            .map(|proof| proof.signing_key.to_vec());
        // Trusted starts get their own per-email bucket, so a stranger's
        // guessing cannot use it up, and keep the per-(email, address) limit, so
        // a stolen trusted device still cannot guess quickly.
        let (email_action, email_limit) = if trusted {
            ("login-email-trusted", self.limits.login_per_email_trusted)
        } else {
            ("login-email", self.limits.login_per_email)
        };
        // Narrowest first: the address, then this email from this address, and
        // the per-email bucket last. A start refused by an earlier limit never
        // uses up a slot of the shared per-email bucket, so it cannot help
        // anyone lock the owner out.
        let allowed = limits::allow(
            &self.pool,
            "login-ip",
            &ip_subject,
            self.limits.login_per_ip,
        )
        .await?
            && limits::allow(
                &self.pool,
                "login",
                &pair_subject,
                self.limits.login_per_email_and_ip,
            )
            .await?
            && limits::allow(&self.pool, email_action, &email_subject, email_limit).await?;
        if !allowed {
            return Err(AccountError::TooManyAttempts);
        }
        let request = CredentialRequest::<Suite>::deserialize(request)
            .map_err(|_| AccountError::InvalidRequest)?;

        let account: Option<(Uuid, Vec<u8>)> =
            sqlx::query_as("SELECT id, password_file FROM accounts WHERE email = $1")
                .bind(&email)
                .fetch_optional(&self.pool)
                .await?;
        let (account_id, password_file) = match account {
            Some((id, bytes)) => (
                Some(id),
                Some(
                    ServerRegistration::<Suite>::deserialize(&bytes)
                        .map_err(|_| AccountError::Internal)?,
                ),
            ),
            None => (None, None),
        };
        let start = ServerLogin::start(
            &mut OsRng,
            self.secrets.setup(),
            password_file,
            request,
            email.as_bytes(),
            ServerLoginParameters {
                context: Some(LOGIN_CONTEXT),
                ..ServerLoginParameters::default()
            },
        )
        .map_err(|_| AccountError::InvalidRequest)?;

        let login_id = Uuid::new_v4();
        let state = zeroize::Zeroizing::new(start.state.serialize().to_vec());
        let sealed = self
            .secrets
            .state_key()
            .seal(
                LOGIN_STATE_CONTEXT,
                &login_state_aad(login_id, account_id),
                &state,
            )
            .map_err(|_| AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO login_states (id, account_id, email_subject, trusted_start, trusted_signer, sealed, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
        )
        .bind(login_id)
        .bind(account_id)
        .bind(email_subject.as_slice())
        .bind(trusted)
        .bind(trusted_signer)
        .bind(sealed.to_bytes())
        .bind(LOGIN_STATE_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(LoginChallenge {
            login_id,
            response: start.message.serialize().to_vec(),
        })
    }

    /// Finishes sign-in and signs the device in. A device the account has not
    /// seen is added as pending. The device signs the login id with its key, so
    /// knowing the password is not enough to act as an existing device.
    pub async fn login_finish(
        &self,
        client: &Client,
        login_id: Uuid,
        finalization: &[u8],
        device: &NewDevice,
        signature: &[u8; 64],
    ) -> Result<NewSession> {
        let name = device.checked_name()?;
        // Taken and deleted at once: a sign-in state is used at most once.
        let row: Option<LoginStateRow> = sqlx::query_as(
            "DELETE FROM login_states WHERE id = $1 AND expires_at > now()
             RETURNING account_id, email_subject, trusted_start, sealed, trusted_signer",
        )
        .bind(login_id)
        .fetch_optional(&self.pool)
        .await?;
        let (account_id, email_subject, trusted_start, sealed, trusted_signer) =
            row.ok_or(AccountError::LoginFailed)?;
        let state = Sealed::from_bytes(&sealed)
            .and_then(|sealed| {
                self.secrets.state_key().open(
                    LOGIN_STATE_CONTEXT,
                    &login_state_aad(login_id, account_id),
                    &sealed,
                )
            })
            .map(zeroize::Zeroizing::new)
            .map_err(|_| AccountError::LoginFailed)?;
        let state =
            ServerLogin::<Suite>::deserialize(&state).map_err(|_| AccountError::LoginFailed)?;
        let verified = CredentialFinalization::<Suite>::deserialize(finalization)
            .ok()
            .and_then(|message| {
                state
                    .finish(
                        message,
                        ServerLoginParameters {
                            context: Some(LOGIN_CONTEXT),
                            ..ServerLoginParameters::default()
                        },
                    )
                    .ok()
            })
            .is_some();
        let account_id = match (verified, account_id) {
            (true, Some(id)) => id,
            (_, account_id) => {
                self.audit(
                    &self.pool,
                    client,
                    account_id,
                    None,
                    AuditAction::LoginFailed,
                )
                .await?;
                return Err(AccountError::LoginFailed);
            }
        };
        orbyn_crypto::verify(
            &device.keys,
            DEVICE_LOGIN_CONTEXT,
            &login_message(login_id.as_bytes(), &device.keys),
            signature,
        )
        .map_err(|_| AccountError::InvalidSignature)?;

        // The password was right. An account with a second factor gets no session and no device
        // row yet, unless a trusted device proved itself at the start: that device holds a device
        // key, which is the factor. The start is given back either way, as for any sign-in that
        // got this far, so the per-email limit counts only passwords that were wrong.
        // A trusted start skips it only for the device that proved itself: one trusted device's
        // proof, made at the start, does not carry a different new device past the factor.
        let skips = trusted_start
            && trusted_signer.as_deref() == Some(device.keys.signing.as_slice())
            && self
                .is_trusted_device(account_id, &device.keys.signing)
                .await?;
        let second_factor = !skips && self.totp_enabled(account_id).await?;
        let give_back = async {
            if let Ok(subject) = <[u8; 32]>::try_from(email_subject.as_slice()) {
                let action = if trusted_start {
                    "login-email-trusted"
                } else {
                    "login-email"
                };
                limits::give_back(&self.pool, action, &subject).await?;
            }
            Ok::<(), AccountError>(())
        };
        if second_factor {
            let login_id = self.begin_second_factor(account_id, device, &name).await?;
            give_back.await?;
            return Err(AccountError::SecondFactorRequired { login_id });
        }
        let session = self
            .complete_login(client, account_id, device, &name)
            .await?;
        // A sign-in that worked gives back the start it was counted for, to the
        // same bucket, so the owner's own sign-ins never use up the per-email limit.
        give_back.await?;
        Ok(session)
    }

    /// Adds the device (pending, unless the account already knows it) and signs it in. The step
    /// shared by a sign-in without a second factor and one that has passed it.
    pub(super) async fn complete_login(
        &self,
        client: &Client,
        account_id: Uuid,
        device: &NewDevice,
        name: &str,
    ) -> Result<NewSession> {
        let mut tx = self.pool.begin().await?;
        // The account first (the deletion takes it before the devices), then the device row. `FOR NO
        // KEY UPDATE` serializes sign-ins, which the pending-device cap below needs, while still letting
        // other transactions' foreign-key checks (`FOR KEY SHARE`) on this account through.
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        let existing: Option<(Uuid, Vec<u8>, String)> = sqlx::query_as(
            "SELECT id, agreement_key, state FROM devices
             WHERE account_id = $1 AND signing_key = $2 AND state <> 'removed' FOR UPDATE",
        )
        .bind(account_id)
        .bind(device.keys.signing.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let (device_id, state) = match existing {
            Some((id, agreement, state)) => {
                if agreement != device.keys.agreement {
                    return Err(AccountError::DeviceKeyConflict);
                }
                (id, DeviceState::parse(&state)?)
            }
            None => {
                // The account is locked above, so concurrent sign-ins cannot pass the cap together.
                let pending: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM devices WHERE account_id = $1 AND state = 'pending'",
                )
                .bind(account_id)
                .fetch_one(&mut *tx)
                .await?;
                if pending >= MAX_PENDING_DEVICES {
                    return Err(AccountError::TooManyAttempts);
                }
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state)
                     VALUES ($1, $2, $3, $4, $5, $6, 'pending')",
                )
                .bind(id)
                .bind(account_id)
                .bind(name)
                .bind(device.platform.as_str())
                .bind(device.keys.signing.as_slice())
                .bind(device.keys.agreement.as_slice())
                .execute(&mut *tx)
                .await?;
                (id, DeviceState::Pending)
            }
        };
        let session = sessions::issue(&mut tx, account_id, device_id, state).await?;
        self.audit(
            &mut *tx,
            client,
            Some(account_id),
            Some(device_id),
            AuditAction::LoginSucceeded,
        )
        .await?;
        tx.commit().await?;
        Ok(session)
    }

    /// Whether the account has a trusted device with this signing key right now.
    async fn is_trusted_device(&self, account_id: Uuid, signing_key: &[u8; 32]) -> Result<bool> {
        let found: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM devices WHERE account_id = $1 AND signing_key = $2 AND state = 'trusted'",
        )
        .bind(account_id)
        .bind(signing_key.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    /// Whether `proof` is a fresh signature over this start by a device that is
    /// trusted on the account with this email.
    async fn is_trusted_start(
        &self,
        email: &str,
        request: &[u8],
        proof: &TrustedStart,
    ) -> Result<bool> {
        let now = unix_now_secs();
        if (now - proof.signed_at).abs() > TRUSTED_START_WINDOW_SECS {
            return Ok(false);
        }
        let signer = orbyn_crypto::DevicePublic {
            signing: proof.signing_key,
            agreement: [0; 32],
        };
        let message = orbyn_auth_client::trusted_start_message(email, request, proof.signed_at);
        if orbyn_crypto::verify(
            &signer,
            orbyn_auth_client::TRUSTED_START_CONTEXT,
            &message,
            &proof.signature,
        )
        .is_err()
        {
            return Ok(false);
        }
        let trusted: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM devices d JOIN accounts a ON a.id = d.account_id
             WHERE a.email = $1 AND d.signing_key = $2 AND d.state = 'trusted'",
        )
        .bind(email)
        .bind(proof.signing_key.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(trusted.is_some())
    }

    /// Checks that `session` belongs to a device that is trusted right now.
    pub(super) async fn require_trusted(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
    ) -> Result<DevicePublic> {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT signing_key, agreement_key FROM devices
             WHERE id = $1 AND account_id = $2 AND state = 'trusted'",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let (signing, agreement) = row.ok_or(AccountError::DeviceNotTrusted)?;
        public_keys(&signing, &agreement)
    }
}

impl Accounts {
    /// Like [`Accounts::require_trusted`], and keeps the device row share-locked until the
    /// transaction ends, so the device cannot be removed under a step that relies on it.
    pub(super) async fn require_trusted_locked(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
    ) -> Result<DevicePublic> {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT signing_key, agreement_key FROM devices
             WHERE id = $1 AND account_id = $2 AND state = 'trusted' FOR SHARE",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let (signing, agreement) = row.ok_or(AccountError::DeviceNotTrusted)?;
        public_keys(&signing, &agreement)
    }

    /// Takes the account's row lock, the first lock of every deletion step, and says when its
    /// deletion is scheduled. `None` when the account is gone.
    pub(super) async fn lock_account(
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<Option<(String, Option<DateTime<Utc>>)>> {
        Ok(sqlx::query_as(
            "SELECT email, deletion_scheduled_at FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?)
    }

    /// Takes the account's row lock shared, as the first statement of a transaction that will write
    /// an audit row or touch the account's devices, sessions or approvals. The account deletion holds
    /// this lock exclusively and then deletes those rows, so every writer takes the account first and
    /// the rows after: the other order can deadlock with it.
    pub(super) async fn lock_account_shared(
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<()> {
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR SHARE")
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Takes the account's row lock shared and refuses while a deletion is scheduled: for the steps
    /// that must not run during the grace period. A scheduling holds the lock exclusively, so
    /// either this sees the schedule, or the schedule waits for this step to finish.
    pub(super) async fn refuse_during_deletion_shared(
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<()> {
        Self::lock_account_shared(tx, account_id).await?;
        Self::refuse_during_deletion(tx, account_id).await
    }

    /// Refuses with [`AccountError::DeletionScheduled`] when a deletion is scheduled. Call it with
    /// the account's row lock held, so a scheduling cannot slip in between.
    pub(super) async fn refuse_during_deletion(
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<()> {
        let scheduled: Option<bool> = sqlx::query_scalar(
            "SELECT deletion_scheduled_at IS NOT NULL FROM accounts WHERE id = $1",
        )
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?;
        if scheduled == Some(true) {
            return Err(AccountError::DeletionScheduled);
        }
        Ok(())
    }
}
