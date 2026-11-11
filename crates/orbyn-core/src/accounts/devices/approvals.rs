//! Approval lifecycle: create, compare nonces and confirm.

use super::*;

impl Accounts {
    /// Step 1, from a trusted device: opens approval `approval_id` (chosen by
    /// the approver) for `device_id`, made at `created_at` (Unix seconds, near
    /// the server's clock), with its commitment. Any earlier open approval for
    /// the device closes. The device is pending, or trusted here and approved
    /// again because the approver's own check finds no approval it verifies;
    /// the server cannot tell which, so it takes either.
    pub async fn create_approval(
        &self,
        client: &Client,
        session: &Session,
        device_id: Uuid,
        approval_id: Uuid,
        created_at: i64,
        commitment: &[u8; 32],
    ) -> Result<Approval> {
        if !fresh(created_at, Utc::now().timestamp()) {
            return Err(AccountError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        // Adding a device waits while a deletion is scheduled, under the shared account lock like
        // the other frozen steps.
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        self.require_trusted(&mut tx, session).await?;
        if device_id == session.device_id {
            return Err(AccountError::InvalidRequest);
        }
        self.device(&mut tx, session.account_id, device_id)
            .await?
            .filter(|d| matches!(d.state, DeviceState::Pending | DeviceState::Trusted))
            .ok_or(AccountError::NotFound)?;
        let taken: Option<i32> = sqlx::query_scalar("SELECT 1 FROM device_approvals WHERE id = $1")
            .bind(approval_id)
            .fetch_optional(&mut *tx)
            .await?;
        if taken.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        sqlx::query(
            "UPDATE device_approvals SET state = 'closed' WHERE device_id = $1 AND state = 'open'",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        let expires_at: DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO device_approvals
                 (id, account_id, device_id, approver_id, approval_created_at, commitment, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
             RETURNING expires_at",
        )
        .bind(approval_id)
        .bind(session.account_id)
        .bind(device_id)
        .bind(session.device_id)
        .bind(created_at)
        .bind(commitment.as_slice())
        .bind(APPROVAL_TTL.as_secs_f64())
        .fetch_one(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(device_id),
            AuditAction::ApprovalCreated,
        )
        .await?;
        tx.commit().await?;
        Ok(Approval {
            id: approval_id,
            expires_at,
        })
    }

    /// The approval as the approver sees it, to read the new device's nonce.
    pub async fn approval(&self, session: &Session, approval_id: Uuid) -> Result<ApprovalView> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, true)
            .await?;
        tx.commit().await?;
        Ok(view)
    }

    /// Step 2, from the pending device, once: its nonce.
    pub async fn submit_device_nonce(
        &self,
        session: &Session,
        approval_id: Uuid,
        nonce: &[u8; 32],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, false)
            .await?;
        if view.device_nonce.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        sqlx::query("UPDATE device_approvals SET device_nonce = $2 WHERE id = $1")
            .bind(approval_id)
            .bind(nonce.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 3, from the approver, once and only after the new device's nonce:
    /// its own nonce, checked against the commitment. A wrong one closes the
    /// approval.
    pub async fn reveal_approver_nonce(
        &self,
        session: &Session,
        approval_id: Uuid,
        nonce: &[u8; 32],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, true)
            .await?;
        if view.device_nonce.is_none() || view.approver_nonce.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        let ids = (
            *view.id.as_bytes(),
            *view.approver_id.as_bytes(),
            *view.device_id.as_bytes(),
        );
        let account = *session.account_id.as_bytes();
        let expected = approval_commitment(&pairing_of(&account, &view, &ids), nonce);
        if !constant_time_eq(&expected, &view.commitment) {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidCommitment);
        }
        sqlx::query("UPDATE device_approvals SET approver_nonce = $2 WHERE id = $1")
            .bind(approval_id)
            .bind(nonce.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 4, from the approver after the person confirmed the codes match:
    /// its signature over the approval and its endorsement. A bad signature
    /// closes the approval.
    pub async fn confirm_approval(
        &self,
        session: &Session,
        approval_id: Uuid,
        signature: &[u8; 64],
        endorsement: Option<&[u8]>,
    ) -> Result<()> {
        if endorsement.is_some_and(|e| e.is_empty() || e.len() > MAX_ENDORSEMENT) {
            return Err(AccountError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        // The account first (the deletion takes it before the devices), shared, and refuse while a
        // deletion is scheduled: an approval already under way cannot finish in the grace period.
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        self.require_trusted(&mut tx, session).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, true)
            .await?;
        if view.approver_nonce.is_none() || view.signature.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        let ids = (
            *view.id.as_bytes(),
            *view.approver_id.as_bytes(),
            *view.device_id.as_bytes(),
        );
        let account = *session.account_id.as_bytes();
        if verify_approval(
            &view.approver_keys,
            &pairing_of(&account, &view, &ids),
            endorsement,
            signature,
        )
        .is_err()
        {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidSignature);
        }
        sqlx::query("UPDATE device_approvals SET signature = $2, endorsement = $3 WHERE id = $1")
            .bind(approval_id)
            .bind(signature.as_slice())
            .bind(endorsement)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Either device cancels the approval, for example when the codes differ.
    pub async fn cancel_approval(&self, session: &Session, approval_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = self.approval_row(&mut tx, session, approval_id).await?;
        if row.approver_id != session.device_id && row.device_id != session.device_id {
            return Err(AccountError::NotFound);
        }
        close(&mut tx, approval_id).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 5, from the device being approved after the person confirmed: the
    /// six digits it shows. One try: a wrong code closes the approval. On the
    /// right code, with the approver still trusted and its signature still
    /// valid, the device becomes trusted, or a trusted device's approval is
    /// replaced by this one.
    pub async fn submit_approval_code(
        &self,
        client: &Client,
        session: &Session,
        approval_id: Uuid,
        code: &str,
    ) -> Result<Device> {
        let device_subject = self
            .secrets
            .digest("approval-device", session.device_id.as_bytes());
        let ip_subject = self.ip_digest(client);
        let by_device = limits::allow(
            &self.pool,
            "approval-code",
            &device_subject,
            self.limits.approval_code_per_device,
        )
        .await?;
        let by_ip = limits::allow(
            &self.pool,
            "approval-code-ip",
            &ip_subject,
            self.limits.approval_code_per_ip,
        )
        .await?;
        if !(by_device && by_ip) {
            return Err(AccountError::TooManyAttempts);
        }

        let mut tx = self.pool.begin().await?;
        // The account first (the deletion takes it before the approval's row), then the approval.
        Self::lock_account_shared(&mut tx, session.account_id).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, false)
            .await?;
        let (Some(device_nonce), Some(approver_nonce)) = (view.device_nonce, view.approver_nonce)
        else {
            return Err(AccountError::ApprovalOutOfOrder);
        };
        let Some(signature) = view.signature else {
            return Err(AccountError::ApprovalNotConfirmed);
        };
        let ids = (
            *view.id.as_bytes(),
            *view.approver_id.as_bytes(),
            *view.device_id.as_bytes(),
        );
        let account = *session.account_id.as_bytes();
        let pairing = pairing_of(&account, &view, &ids);
        let sas = approval_sas(&pairing, &approver_nonce, &device_nonce);
        if !constant_time_eq(sas.as_bytes(), code.trim().as_bytes()) {
            close(&mut tx, approval_id).await?;
            self.audit(
                &mut *tx,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::ApprovalCodeWrong,
            )
            .await?;
            tx.commit().await?;
            return Err(AccountError::WrongCode { remaining: 0 });
        }
        // Check the approval again against the devices as they are now.
        let approver_trusted = self
            .device(&mut tx, session.account_id, view.approver_id)
            .await?
            .is_some_and(|d| d.state == DeviceState::Trusted && d.keys == view.approver_keys);
        let signed = if approver_trusted {
            verify_approval(
                &view.approver_keys,
                &pairing,
                view.endorsement.as_deref(),
                &signature,
            )
            .ok()
        } else {
            None
        };
        let Some(signed) = signed else {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidSignature);
        };
        // Only a v2 or v3 signature covers the endorsement, so only then does a hash go with the device.
        let endorsement_hash = match (signed, view.endorsement.as_deref()) {
            (ApprovalSignature::V3 | ApprovalSignature::V2, Some(endorsement)) => {
                Some(endorsement_hash(endorsement))
            }
            _ => None,
        };
        sqlx::query("UPDATE device_approvals SET state = 'used' WHERE id = $1")
            .bind(approval_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE devices SET state = 'trusted', approved_by = $2, approval_signature = $3,
                    approval_id = $4, approval_created_at = $5, approved_at = now(),
                    approval_endorsement_hash = $6
             WHERE id = $1 AND state IN ('pending', 'trusted')",
        )
        .bind(view.device_id)
        .bind(view.approver_id)
        .bind(signature.as_slice())
        .bind(view.id)
        .bind(view.created_at)
        .bind(endorsement_hash.as_ref().map(<[u8; 32]>::as_slice))
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(view.device_id),
            AuditAction::DeviceApproved,
        )
        .await?;
        let device = self
            .device(&mut tx, session.account_id, view.device_id)
            .await?
            .ok_or(AccountError::Internal)?;
        tx.commit().await?;
        Ok(device)
    }
}
