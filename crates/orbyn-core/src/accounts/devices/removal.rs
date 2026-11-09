//! Removing a trusted device with its signed removal sequence.

use super::*;

impl Accounts {
    /// A trusted device removes `device_id`, which may be itself, with its
    /// signature over [`removal_message`] and `sequence`. Its sessions end and
    /// its open approvals close. The last trusted device stays.
    pub async fn remove_device(
        &self,
        client: &Client,
        session: &Session,
        device_id: Uuid,
        sequence: u64,
        signature: &[u8; 64],
    ) -> Result<()> {
        let stored_sequence = i64::try_from(sequence)
            .ok()
            .filter(|_| sequence <= MAX_REMOVAL_SEQUENCE)
            .ok_or(AccountError::InvalidRequest)?;
        let mut tx = self.pool.begin().await?;
        // Lock the account so two removals cannot each leave the other device last.
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        Self::refuse_during_deletion(&mut tx, session.account_id).await?;
        let remover = self.require_trusted(&mut tx, session).await?;
        let target = self
            .device(&mut tx, session.account_id, device_id)
            .await?
            .ok_or(AccountError::NotFound)?;
        let message = removal_message(
            session.account_id.as_bytes(),
            device_id.as_bytes(),
            &target.keys,
            sequence,
        );
        verify_signed(&remover, DEVICE_REMOVAL_CONTEXT, &message, signature)?;
        if target.state == DeviceState::Trusted {
            let trusted: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM devices WHERE account_id = $1 AND state = 'trusted'",
            )
            .bind(session.account_id)
            .fetch_one(&mut *tx)
            .await?;
            if trusted <= 1 {
                return Err(AccountError::LastTrustedDevice);
            }
        }
        sqlx::query(
            "UPDATE devices SET state = 'removed', removed_at = now(), removed_by = $2,
                    removal_signature = $3, removal_sequence = $4
             WHERE id = $1",
        )
        .bind(device_id)
        .bind(session.device_id)
        .bind(signature.as_slice())
        .bind(stored_sequence)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        // A removed device keeps its row for its history, so its wake-up token is deleted here
        // with the subscription it made.
        sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM subscriptions WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE device_approvals SET state = 'closed'
             WHERE (device_id = $1 OR approver_id = $1) AND state = 'open'",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(device_id),
            AuditAction::DeviceRemoved,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
