//! Service envelopes: a zone key sealed to the account's service key, kept beside the envelopes
//! sealed to its devices (docs/key-service.md). The server stores the bytes and never opens them. It
//! checks only what it can without opening one: that the sender is a trusted device, that the
//! account's newest stored protection setting is not Advanced, and that the statement hash the
//! envelope names is the one of the certification the server holds for the account. Devices check
//! the certification itself (the identity's signature, then the transparency log).

use crate::{Result, Store, StoreError, check_zone_name, keychain::KEY_ID_LEN, require_trusted};
use orbyn_core::accounts::{Session, limits};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

/// The most (zone, key id) pairs `service_missing` answers at once: devices send them 100 at a time.
pub const SERVICE_MISSING_PAGE: usize = 100;

/// The account's service key as the key service certified it. All of it is public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCertification {
    pub identity_version: u32,
    /// The compressed P-256 service public key (33 bytes).
    pub public_key: Vec<u8>,
    /// The signed statement (77 bytes) and the identity's signature over it (64 bytes).
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
    /// SHA-256 of the statement, which a service envelope names.
    pub statement_hash: [u8; 32],
}

/// A certification to remember. The statement hash is **not** part of it: the store computes it
/// from the statement, so a caller cannot give the account a hash that the statement does not have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewServiceCertification {
    pub identity_version: u32,
    /// The compressed P-256 service public key (33 bytes).
    pub public_key: Vec<u8>,
    /// The signed statement (77 bytes) and the identity's signature over it (64 bytes).
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A service envelope a device sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewServiceEnvelope {
    pub zone: String,
    pub key_id: Vec<u8>,
    pub envelope: Vec<u8>,
    /// The statement hash of the certification the envelope was sealed against.
    pub statement_hash: [u8; 32],
}

/// A stored service envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEnvelope {
    pub sender_device_id: Uuid,
    pub zone: String,
    pub key_id: Vec<u8>,
    pub envelope: Vec<u8>,
    pub statement_hash: [u8; 32],
}

/// A zone key some device holds an envelope for and the service holds none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingServiceEnvelope {
    pub zone: String,
    pub key_id: Vec<u8>,
}

/// A certification row: identity version, public key, statement, signature, statement hash.
type CertificationRow = (i32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
/// A service envelope row: sender, zone, key id, envelope, statement hash.
type EnvelopeRow = (Uuid, String, Vec<u8>, Vec<u8>, Vec<u8>);

fn hash_of(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| StoreError::Internal)
}

impl Store {
    /// Remembers the account's certification, as the key service answered it. The account has
    /// one: a newer one (another identity version, a new generation) replaces it. Public data,
    /// written by the record server itself, not on behalf of a device. **Under the account's lock,
    /// and refused for an account whose newest stored setting is Advanced** (`ProtectionAdvanced`),
    /// so a key service answer that was in flight when the person switched cannot bring back what
    /// the switch removed. The statement hash is computed here.
    pub async fn put_service_certification(
        &self,
        account_id: Uuid,
        certification: &NewServiceCertification,
    ) -> Result<()> {
        if certification.public_key.len() != 33
            || certification.statement.len() != 77
            || certification.signature.len() != 64
            || certification.identity_version == 0
        {
            return Err(StoreError::InvalidEnvelope);
        }
        let hash: [u8; 32] = Sha256::digest(&certification.statement).into();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        if newest_level_is_advanced(&mut tx, account_id).await? {
            return Err(StoreError::ProtectionAdvanced);
        }
        sqlx::query(
            "INSERT INTO account_service_keys
                 (account_id, identity_version, public_key, statement, statement_hash, signature)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (account_id) DO UPDATE
             SET identity_version = EXCLUDED.identity_version, public_key = EXCLUDED.public_key,
                 statement = EXCLUDED.statement, statement_hash = EXCLUDED.statement_hash,
                 signature = EXCLUDED.signature, created_at = now()",
        )
        .bind(account_id)
        .bind(i32::try_from(certification.identity_version).map_err(|_| StoreError::Internal)?)
        .bind(&certification.public_key)
        .bind(&certification.statement)
        .bind(hash.as_slice())
        .bind(&certification.signature)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The certification the server holds for the account, if any.
    pub async fn service_certification(
        &self,
        account_id: Uuid,
    ) -> Result<Option<ServiceCertification>> {
        let row: Option<CertificationRow> = sqlx::query_as(
            "SELECT identity_version, public_key, statement, signature, statement_hash
             FROM account_service_keys WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(version, public_key, statement, signature, hash)| {
            Ok(ServiceCertification {
                identity_version: u32::try_from(version).map_err(|_| StoreError::Internal)?,
                public_key,
                statement,
                signature,
                statement_hash: hash_of(hash)?,
            })
        })
        .transpose()
    }

    /// Stores service envelopes from the session's device, all or nothing; one for the same zone
    /// and key id replaces the earlier. The device must be trusted, the account's newest stored
    /// protection setting must not be Advanced (`ProtectionAdvanced`), the account must have a
    /// certification (`NoServiceKey`) and every envelope must name its statement hash
    /// (`ServiceKeyChanged` otherwise). The service recipient has its own cap, as a device does.
    pub async fn put_service_envelopes(
        &self,
        session: &Session,
        envelopes: &[NewServiceEnvelope],
    ) -> Result<()> {
        if envelopes.is_empty() || envelopes.len() > self.limits.max_envelope_batch {
            return Err(StoreError::BatchTooLarge);
        }
        self.check_service_envelopes(envelopes)?;
        let mut tx = self.pool.begin().await?;
        // The account first, then devices, as every envelope upload does; it also serializes the
        // uploads of one account, so the count is exact and a switch to Advanced cannot slip
        // between the check and the write.
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        require_trusted(&mut *tx, session, true).await?;
        self.write_service_envelopes(&mut tx, session, envelopes)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The checks that need no database: sizes, names and no repeated zone and key id.
    pub(crate) fn check_service_envelopes(&self, envelopes: &[NewServiceEnvelope]) -> Result<()> {
        let mut seen = BTreeSet::new();
        for e in envelopes {
            check_zone_name(&e.zone)?;
            let valid = e.key_id.len() == KEY_ID_LEN
                && !e.envelope.is_empty()
                && e.envelope.len() <= self.limits.max_envelope
                && seen.insert((e.zone.as_str(), e.key_id.as_slice()));
            if !valid {
                return Err(StoreError::InvalidEnvelope);
            }
        }
        Ok(())
    }

    /// The writes and the checks that need the account, inside the caller's transaction, which
    /// already holds the account's lock and has found the device trusted.
    pub(crate) async fn write_service_envelopes(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        session: &Session,
        envelopes: &[NewServiceEnvelope],
    ) -> Result<()> {
        if newest_level_is_advanced(tx, session.account_id).await? {
            return Err(StoreError::ProtectionAdvanced);
        }
        // While the account's deletion is scheduled nothing is written to the service's copy: a
        // stolen device could otherwise replace the envelopes with junk during the grace period,
        // as it cannot rotate a zone key then.
        let scheduled: Option<bool> = sqlx::query_scalar(
            "SELECT deletion_scheduled_at IS NOT NULL FROM accounts WHERE id = $1",
        )
        .bind(session.account_id)
        .fetch_optional(&mut **tx)
        .await?;
        if scheduled == Some(true) {
            return Err(StoreError::DeletionScheduled);
        }
        let held: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT statement_hash FROM account_service_keys WHERE account_id = $1",
        )
        .bind(session.account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let held = hash_of(held.ok_or(StoreError::NoServiceKey)?)?;
        if envelopes.iter().any(|e| e.statement_hash != held) {
            return Err(StoreError::ServiceKeyChanged);
        }
        for e in envelopes {
            sqlx::query(
                "INSERT INTO key_envelopes
                     (account_id, recipient_kind, recipient_device_id, sender_device_id, zone,
                      key_id, envelope, service_statement_hash)
                 VALUES ($1, 'service', NULL, $2, $3, $4, $5, $6)
                 ON CONFLICT (account_id, zone, key_id) WHERE recipient_kind = 'service'
                 DO UPDATE SET sender_device_id = EXCLUDED.sender_device_id,
                     envelope = EXCLUDED.envelope,
                     service_statement_hash = EXCLUDED.service_statement_hash,
                     created_at = now()",
            )
            .bind(session.account_id)
            .bind(session.device_id)
            .bind(&e.zone)
            .bind(&e.key_id)
            .bind(&e.envelope)
            .bind(e.statement_hash.as_slice())
            .execute(&mut **tx)
            .await?;
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM key_envelopes WHERE account_id = $1 AND recipient_kind = 'service'",
        )
        .bind(session.account_id)
        .fetch_one(&mut **tx)
        .await?;
        if count > self.limits.max_envelopes_per_device {
            return Err(StoreError::TooManyEnvelopes);
        }
        Ok(())
    }

    /// Counts one ask for the account's service key against its hourly limit, for a trusted
    /// device. The record server calls the key service only after this.
    pub async fn begin_service_key_ask(&self, session: &Session) -> Result<()> {
        require_trusted(&self.pool, session, false).await?;
        // Before the key service is asked to make anything: an Advanced account gets no key, and
        // neither does one whose deletion is scheduled. This read is not under the account lock; a
        // switch that lands after it is caught when the certification is kept
        // ([`Store::queue_service_key_retire`]).
        let (advanced, scheduled): (Option<String>, Option<bool>) = sqlx::query_as(
            "SELECT (SELECT level FROM protection_settings WHERE account_id = a.id
                     ORDER BY seq DESC LIMIT 1),
                    a.deletion_scheduled_at IS NOT NULL
             FROM accounts a WHERE a.id = $1",
        )
        .bind(session.account_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::DeviceNotTrusted)?;
        if advanced.as_deref() == Some("advanced") {
            return Err(StoreError::ProtectionAdvanced);
        }
        if scheduled == Some(true) {
            return Err(StoreError::DeletionScheduled);
        }
        let subject: [u8; 32] = Sha256::digest(session.account_id.as_bytes()).into();
        let allowed = limits::allow(
            &self.pool,
            "service-key-ask",
            &subject,
            self.limits.service_key_asks_per_hour,
        )
        .await?;
        if allowed {
            Ok(())
        } else {
            Err(StoreError::TooManyServiceKeyAsks)
        }
    }

    /// Queues a retire of the account's service key, for a key the key service made after the
    /// person switched to Advanced (the switch's own job may already have run, finding nothing to
    /// retire). One job per call: retiring is idempotent there.
    pub async fn queue_service_key_retire(&self, account_id: Uuid) -> Result<()> {
        orbyn_core::jobs::enqueue_with_attempts(
            &self.pool,
            crate::SERVICE_KEY_RETIRE_JOB,
            serde_json::json!({"account_id": account_id}),
            Some(&format!("{account_id}:late:{}", Uuid::new_v4())),
            crate::SERVICE_KEY_RETIRE_ATTEMPTS,
        )
        .await?;
        Ok(())
    }

    /// The service envelopes of the session's account, for a test or the recovery that will open
    /// them. Oldest first.
    pub async fn list_service_envelopes(&self, session: &Session) -> Result<Vec<ServiceEnvelope>> {
        require_trusted(&self.pool, session, false).await?;
        let rows: Vec<EnvelopeRow> = sqlx::query_as(
            "SELECT sender_device_id, zone, key_id, envelope, service_statement_hash
             FROM key_envelopes WHERE account_id = $1 AND recipient_kind = 'service'
             ORDER BY created_at, zone, key_id",
        )
        .bind(session.account_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(sender_device_id, zone, key_id, envelope, hash)| {
                Ok(ServiceEnvelope {
                    sender_device_id,
                    zone,
                    key_id,
                    envelope,
                    statement_hash: hash_of(hash)?,
                })
            })
            .collect()
    }

    /// Up to [`SERVICE_MISSING_PAGE`] zone keys the account's devices hold envelopes for and the
    /// service holds none, in zone and key order. Empty when the account's newest stored setting is
    /// Advanced: nothing is copied for it. The session's device must be trusted.
    pub async fn service_missing(&self, session: &Session) -> Result<Vec<MissingServiceEnvelope>> {
        require_trusted(&self.pool, session, false).await?;
        let mut conn = self.pool.acquire().await?;
        let advanced: Option<String> = sqlx::query_scalar(
            "SELECT level FROM protection_settings WHERE account_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(session.account_id)
        .fetch_optional(&mut *conn)
        .await?;
        if advanced.as_deref() == Some("advanced") {
            return Ok(Vec::new());
        }
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT DISTINCT d.zone, d.key_id FROM key_envelopes d
             WHERE d.account_id = $1 AND d.recipient_kind = 'device'
               AND NOT EXISTS (
                   SELECT 1 FROM key_envelopes s
                   WHERE s.account_id = d.account_id AND s.recipient_kind = 'service'
                     AND s.zone = d.zone AND s.key_id = d.key_id)
             ORDER BY d.zone, d.key_id LIMIT $2",
        )
        .bind(session.account_id)
        .bind(i64::try_from(SERVICE_MISSING_PAGE).map_err(|_| StoreError::Internal)?)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(zone, key_id)| MissingServiceEnvelope { zone, key_id })
            .collect())
    }
}

async fn newest_level_is_advanced(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
) -> Result<bool> {
    let level: Option<String> = sqlx::query_scalar(
        "SELECT level FROM protection_settings WHERE account_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(level.as_deref() == Some("advanced"))
}
