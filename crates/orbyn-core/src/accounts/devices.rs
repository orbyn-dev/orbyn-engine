//! Trusted devices, approvals and removals.
//!
//! An approval is a two-way comparison between a trusted device (the approver)
//! and a pending one, so neither has to take the server's word for the other's
//! keys. In order, each step once:
//!
//! 1. The approver creates the approval with an id and time it chose and a
//!    commitment to a random nonce, bound to both devices' keys.
//! 2. The pending device, holding the commitment, sends its own nonce.
//! 3. The approver, holding that nonce, reveals its own; the server checks it
//!    against the commitment.
//! 4. Both devices show six digits computed from both nonces and both keys.
//!    When the person confirms on the approver that they match, it signs the
//!    approval (and its list of trusted devices).
//! 5. When the person confirms on the new device, it sends the digits; the
//!    server checks them once and trusts the device. A mismatch or a cancel
//!    closes the approval, and a new one is needed.
//!
//! Removing a device carries the remover's signature, which every device checks.

use super::{
    AccountError, Accounts, App, Approval, AuditAction, Client, Device, DeviceState, Platform,
    Removal, Result, Session, limits, public_keys,
};
use chrono::{DateTime, Utc};
use orbyn_auth_client::{
    DEVICE_APPROVAL_CONTEXT, DEVICE_APPROVAL_V2_CONTEXT, DEVICE_APPROVAL_V3_CONTEXT,
    DEVICE_REMOVAL_CONTEXT, Descriptor, MAX_REMOVAL_SEQUENCE, Pairing, approval_commitment,
    approval_message, approval_message_v2, approval_message_v3, approval_sas, endorsement_hash,
    removal_message,
};
use orbyn_crypto::DevicePublic;
use sqlx::{Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

mod approvals;
mod removal;

/// How long an approval stays open.
pub const APPROVAL_TTL: Duration = Duration::from_secs(10 * 60);
/// How far an approver's clock may be from the server's, in seconds.
pub const CLOCK_SLACK_SECS: i64 = 5 * 60;
/// The largest endorsement an approver may attach.
pub const MAX_ENDORSEMENT: usize = 16 * 1024;

fn fresh(created_at: i64, now: i64) -> bool {
    (created_at - now).abs() <= CLOCK_SLACK_SECS
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
    /// The device's stored name, platform and app label. The commitment, the digits and the
    /// approval signature cover them when the device has a label.
    pub device_name: String,
    pub device_platform: Platform,
    pub device_app: Option<App>,
    pub commitment: [u8; 32],
    pub device_nonce: Option<[u8; 32]>,
    pub approver_nonce: Option<[u8; 32]>,
    pub signature: Option<[u8; 64]>,
    pub endorsement: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: Uuid,
    name: String,
    platform: String,
    app: Option<String>,
    state: String,
    signing_key: Vec<u8>,
    agreement_key: Vec<u8>,
    created_at: DateTime<Utc>,
    approved_by: Option<Uuid>,
    approval_signature: Option<Vec<u8>>,
    approval_id: Option<Uuid>,
    approval_created_at: Option<i64>,
    approval_endorsement_hash: Option<Vec<u8>>,
}

/// id, signing key, agreement key, removed by, removal sequence, removal signature.
type RemovalRow = (Uuid, Vec<u8>, Vec<u8>, Uuid, i64, Vec<u8>);

#[derive(sqlx::FromRow)]
struct ApprovalRow {
    id: Uuid,
    account_id: Uuid,
    expires_at: DateTime<Utc>,
    approval_created_at: Option<i64>,
    approver_id: Uuid,
    approver_signing: Vec<u8>,
    approver_agreement: Vec<u8>,
    device_id: Uuid,
    device_signing: Vec<u8>,
    device_agreement: Vec<u8>,
    device_name: String,
    device_platform: String,
    device_app: Option<String>,
    commitment: Option<Vec<u8>>,
    device_nonce: Option<Vec<u8>>,
    approver_nonce: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    endorsement: Option<Vec<u8>>,
    state: String,
    expired: bool,
}

/// A `SELECT` of every [`DeviceRow`] column with `$tail` appended, as one literal.
macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT id, name, platform, app, state, signing_key, agreement_key, created_at, ",
            "approved_by, approval_signature, approval_id, approval_created_at, ",
            "approval_endorsement_hash FROM devices ",
            $tail
        )
    };
}

const SELECT_APPROVAL: &str = "SELECT a.id, a.account_id, a.expires_at, a.approval_created_at,
        a.approver_id, ad.signing_key AS approver_signing, ad.agreement_key AS approver_agreement,
        a.device_id, d.signing_key AS device_signing, d.agreement_key AS device_agreement,
        d.name AS device_name, d.platform AS device_platform, d.app AS device_app,
        a.commitment, a.device_nonce, a.approver_nonce, a.signature, a.endorsement, a.state,
        a.expires_at <= now() AS expired
     FROM device_approvals a
     JOIN devices ad ON ad.id = a.approver_id
     JOIN devices d ON d.id = a.device_id
     WHERE a.id = $1 AND a.account_id = $2 FOR UPDATE OF a";

impl TryFrom<DeviceRow> for Device {
    type Error = AccountError;

    fn try_from(row: DeviceRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            name: row.name,
            platform: Platform::parse(&row.platform)?,
            app: App::parse_opt(row.app.as_deref())?,
            state: DeviceState::parse(&row.state).map_err(|_| AccountError::Internal)?,
            keys: public_keys(&row.signing_key, &row.agreement_key)?,
            created_at: row.created_at,
            approved_by: row.approved_by,
            approval_signature: row
                .approval_signature
                .map(|s| s.as_slice().try_into().map_err(|_| AccountError::Internal))
                .transpose()?,
            approval_id: row.approval_id,
            approval_created_at: row.approval_created_at,
            approval_endorsement_hash: fixed(row.approval_endorsement_hash)?,
        })
    }
}

fn fixed<const N: usize>(bytes: Option<Vec<u8>>) -> Result<Option<[u8; N]>> {
    bytes
        .map(|b| b.as_slice().try_into().map_err(|_| AccountError::Internal))
        .transpose()
}

impl TryFrom<ApprovalRow> for ApprovalView {
    type Error = AccountError;

    fn try_from(row: ApprovalRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            expires_at: row.expires_at,
            created_at: row
                .approval_created_at
                .ok_or(AccountError::ApprovalExpired)?,
            approver_id: row.approver_id,
            approver_keys: public_keys(&row.approver_signing, &row.approver_agreement)?,
            device_id: row.device_id,
            device_keys: public_keys(&row.device_signing, &row.device_agreement)?,
            device_name: row.device_name,
            device_platform: Platform::parse(&row.device_platform)?,
            device_app: App::parse_opt(row.device_app.as_deref())?,
            commitment: fixed(row.commitment)?.ok_or(AccountError::ApprovalExpired)?,
            device_nonce: fixed(row.device_nonce)?,
            approver_nonce: fixed(row.approver_nonce)?,
            signature: fixed(row.signature)?,
            endorsement: row.endorsement,
        })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn pairing_of<'a>(
    account_id: &'a [u8; 16],
    view: &'a ApprovalView,
    ids: &'a ([u8; 16], [u8; 16], [u8; 16]),
) -> Pairing<'a> {
    Pairing {
        account_id,
        approval_id: &ids.0,
        created_at: view.created_at,
        approver_id: &ids.1,
        approver: &view.approver_keys,
        device_id: &ids.2,
        device: &view.device_keys,
        descriptor: view.device_app.map(|app| Descriptor {
            name: &view.device_name,
            platform: view.device_platform.as_str(),
            app: app.as_str(),
        }),
    }
}

/// How an approval signature verified: under the v3 message of a device that named its app, the
/// v2 message that covers the endorsement, or the v1 message of an approver that predates it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalSignature {
    V3,
    V2,
    V1,
}

/// Checks an approver's signature on an approval. For a device that named its app, only the v3
/// message over its description and the endorsement's hash counts, and an approval without an
/// endorsement fails: no older message covers what the approver was shown. For any other device,
/// the v2 message over the endorsement's hash when an endorsement came with it, else (or when that
/// fails, for an older approver) the v1 message.
fn verify_approval(
    signer: &DevicePublic,
    pairing: &Pairing<'_>,
    endorsement: Option<&[u8]>,
    signature: &[u8; 64],
) -> Result<ApprovalSignature> {
    if pairing.descriptor.is_some() {
        let message = endorsement
            .and_then(|e| approval_message_v3(pairing, &endorsement_hash(e)))
            .ok_or(AccountError::InvalidSignature)?;
        verify_signed(signer, DEVICE_APPROVAL_V3_CONTEXT, &message, signature)?;
        return Ok(ApprovalSignature::V3);
    }
    if let Some(endorsement) = endorsement {
        let message = approval_message_v2(pairing, &endorsement_hash(endorsement));
        if verify_signed(signer, DEVICE_APPROVAL_V2_CONTEXT, &message, signature).is_ok() {
            return Ok(ApprovalSignature::V2);
        }
    }
    verify_signed(
        signer,
        DEVICE_APPROVAL_CONTEXT,
        &approval_message(pairing),
        signature,
    )?;
    Ok(ApprovalSignature::V1)
}

fn verify_signed(
    signer: &DevicePublic,
    context: &str,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    orbyn_crypto::verify(signer, context, message, signature)
        .map_err(|_| AccountError::InvalidSignature)
}

impl Accounts {
    async fn device(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<Device>> {
        let row: Option<DeviceRow> = sqlx::query_as(select_devices!(
            "WHERE id = $1 AND account_id = $2 AND state <> 'removed'"
        ))
        .bind(device_id)
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?;
        row.map(Device::try_from).transpose()
    }

    /// The account's devices, for a trusted device, and the signed records of
    /// devices removed from it.
    pub async fn list_devices(&self, session: &Session) -> Result<(Vec<Device>, Vec<Removal>)> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let rows: Vec<DeviceRow> = sqlx::query_as(select_devices!(
            "WHERE account_id = $1 AND state <> 'removed' ORDER BY created_at, id"
        ))
        .bind(session.account_id)
        .fetch_all(&mut *tx)
        .await?;
        let removed: Vec<RemovalRow> = sqlx::query_as(
            "SELECT id, signing_key, agreement_key, removed_by, removal_sequence, removal_signature
             FROM devices
             WHERE account_id = $1 AND state = 'removed' AND removal_signature IS NOT NULL
             ORDER BY removed_at, id",
        )
        .bind(session.account_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let devices = rows
            .into_iter()
            .map(Device::try_from)
            .collect::<Result<_>>()?;
        let removals = removed
            .into_iter()
            .map(
                |(device_id, signing, agreement, removed_by, sequence, signature)| {
                    Ok(Removal {
                        device_id,
                        keys: public_keys(&signing, &agreement)?,
                        removed_by,
                        sequence: u64::try_from(sequence).map_err(|_| AccountError::Internal)?,
                        signature: signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| AccountError::Internal)?,
                    })
                },
            )
            .collect::<Result<_>>()?;
        Ok((devices, removals))
    }

    /// The calling device, and its open approval if a trusted device made one.
    pub async fn current_device(
        &self,
        session: &Session,
    ) -> Result<(Device, Option<ApprovalView>)> {
        let mut tx = self.pool.begin().await?;
        let device = self
            .device(&mut tx, session.account_id, session.device_id)
            .await?
            .ok_or(AccountError::Unauthorized)?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM device_approvals
             WHERE device_id = $1 AND account_id = $2 AND state = 'open' AND expires_at > now()
               AND commitment IS NOT NULL",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let approval = match id {
            Some(id) => Some(self.approval_row(&mut tx, session, id).await?.try_into()?),
            None => None,
        };
        tx.commit().await?;
        Ok((device, approval))
    }

    async fn approval_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
        approval_id: Uuid,
    ) -> Result<ApprovalRow> {
        let row: Option<ApprovalRow> = sqlx::query_as(SELECT_APPROVAL)
            .bind(approval_id)
            .bind(session.account_id)
            .fetch_optional(&mut **tx)
            .await?;
        let row = row.ok_or(AccountError::NotFound)?;
        if row.account_id != session.account_id {
            return Err(AccountError::NotFound);
        }
        Ok(row)
    }

    /// The open approval `approval_id` locked for a step by one of its two
    /// devices. `as_approver` says which side the session must be.
    async fn open_approval(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
        approval_id: Uuid,
        as_approver: bool,
    ) -> Result<ApprovalView> {
        let row = self.approval_row(tx, session, approval_id).await?;
        let side = if as_approver {
            row.approver_id
        } else {
            row.device_id
        };
        if side != session.device_id {
            return Err(AccountError::NotFound);
        }
        if row.state != "open" {
            return Err(AccountError::ApprovalExpired);
        }
        if row.expired {
            close(tx, approval_id).await?;
            return Err(AccountError::ApprovalExpired);
        }
        row.try_into()
    }
}

async fn close(tx: &mut Transaction<'_, Postgres>, approval_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE device_approvals SET state = 'closed' WHERE id = $1")
        .bind(approval_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_times_must_be_near_the_server_clock() {
        assert!(fresh(1_000, 1_000));
        assert!(fresh(1_000 - CLOCK_SLACK_SECS, 1_000));
        assert!(fresh(1_000 + CLOCK_SLACK_SECS, 1_000));
        assert!(!fresh(1_000 - CLOCK_SLACK_SECS - 1, 1_000));
        assert!(!fresh(1_000 + CLOCK_SLACK_SECS + 1, 1_000));
    }
}
