//! `/v1/keychain` routes: zone keys one trusted device sealed to another. The
//! store checks that sender and recipients are trusted devices of the account.

use crate::AppState;
use crate::accounts::{Authed, encode, time};
use crate::records::{Answer, Body, Refusal, bytes, store};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use orbyn_contracts as wire;
use orbyn_store::{
    NewEnvelope, NewProtection, NewServiceCertification, NewServiceEnvelope, ProtectionLevel,
    ProtectionRecord, Rotation,
};
use serde::Deserialize;
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/keychain/envelopes",
            get(list_envelopes).post(put_envelopes),
        )
        .route(
            "/v1/keychain/protection",
            get(protection_chain).post(set_protection),
        )
        .route("/v1/keychain/service-key", get(service_key))
        .route("/v1/keychain/service-missing", get(service_missing))
}

fn wire_level(level: ProtectionLevel) -> wire::ProtectionLevel {
    match level {
        ProtectionLevel::Standard => wire::ProtectionLevel::Standard,
        ProtectionLevel::Advanced => wire::ProtectionLevel::Advanced,
    }
}

pub(crate) fn wire_protection(r: ProtectionRecord) -> wire::ProtectionLink {
    wire::ProtectionLink {
        level: wire_level(r.level),
        seq: r.seq,
        prev: encode(&r.prev),
        signed_at: r.signed_at,
        signer_device_id: r.signer_device_id.to_string(),
        signature: encode(&r.signature),
    }
}

async fn set_protection(
    State(state): State<AppState>,
    Authed(session): Authed,
    Body(body): Body<wire::SetProtection>,
) -> Answer<(StatusCode, Json<wire::ProtectionLink>)> {
    let level = match body.level {
        wire::ProtectionLevel::Standard => ProtectionLevel::Standard,
        wire::ProtectionLevel::Advanced => ProtectionLevel::Advanced,
    };
    let new = NewProtection {
        level,
        seq: body.seq,
        prev: bytes(&body.prev)?
            .try_into()
            .map_err(|_| Refusal::BadRequest)?,
        signed_at: body.signed_at,
        signature: bytes(&body.device_signature)?
            .try_into()
            .map_err(|_| Refusal::BadRequest)?,
    };
    let stored = store(&state)?.put_protection(&session, &new).await?;
    Ok((StatusCode::CREATED, Json(wire_protection(stored))))
}

#[derive(Deserialize)]
struct ChainQuery {
    from: Option<u64>,
}

async fn protection_chain(
    State(state): State<AppState>,
    Authed(session): Authed,
    query: Result<Query<ChainQuery>, axum::extract::rejection::QueryRejection>,
) -> Answer<Json<wire::ProtectionChain>> {
    let Query(query) = query.map_err(|_| Refusal::BadRequest)?;
    let (links, more) = store(&state)?
        .protection_chain(&session, query.from.unwrap_or(1))
        .await?;
    Ok(Json(wire::ProtectionChain {
        links: links.into_iter().map(wire_protection).collect(),
        more,
    }))
}

async fn put_envelopes(
    State(state): State<AppState>,
    Authed(session): Authed,
    Body(body): Body<wire::PutKeyEnvelopes>,
) -> Answer<StatusCode> {
    let envelopes = body
        .envelopes
        .into_iter()
        .map(|e| {
            Ok(NewEnvelope {
                recipient_device_id: Uuid::parse_str(&e.recipient_device_id)
                    .map_err(|_| Refusal::BadRequest)?,
                zone: e.zone,
                key_id: bytes(&e.key_id)?,
                envelope: bytes(&e.envelope)?,
                rotation: e
                    .rotation
                    .map(|r| {
                        Answer::Ok(Rotation {
                            previous_key_id: bytes(&r.previous_key_id)?,
                            signer_device_id: Uuid::parse_str(&r.signer_device_id)
                                .map_err(|_| Refusal::BadRequest)?,
                            signature: bytes(&r.signature)?,
                        })
                    })
                    .transpose()?,
            })
        })
        .collect::<Answer<Vec<_>>>()?;
    let service = body
        .service_envelopes
        .unwrap_or_default()
        .into_iter()
        .map(|e| {
            Ok(NewServiceEnvelope {
                zone: e.zone,
                key_id: bytes(&e.key_id)?,
                envelope: bytes(&e.envelope)?,
                statement_hash: bytes(&e.statement_hash)?
                    .try_into()
                    .map_err(|_| Refusal::BadRequest)?,
            })
        })
        .collect::<Answer<Vec<_>>>()?;
    store(&state)?
        .put_envelope_batch(&session, &envelopes, &service)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_envelopes(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::KeyEnvelopeList>> {
    let envelopes = store(&state)?.list_envelopes(&session).await?;
    Ok(Json(wire::KeyEnvelopeList {
        envelopes: envelopes
            .into_iter()
            .map(|e| wire::KeyEnvelope {
                sender_device_id: e.sender_device_id.to_string(),
                zone: e.zone,
                key_id: encode(&e.key_id),
                envelope: encode(&e.envelope),
                created_at: time(e.created_at),
                rotation: e.rotation.map(|r| wire::KeyRotation {
                    previous_key_id: encode(&r.previous_key_id),
                    signer_device_id: r.signer_device_id.to_string(),
                    signature: encode(&r.signature),
                }),
            })
            .collect(),
    }))
}

/// `GET /v1/keychain/service-key`: asks the key service for the account's service key (making it if
/// the account has none), keeps the certification, and answers it. A trusted device asks, ten times
/// an hour per account. The server checks only that the answer is for this account and hangs
/// together (the statement it rebuilds hashes to the hash the key service gave); the identity's
/// signature and the transparency log are the device's to check.
async fn service_key(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<axum::response::Response> {
    use axum::response::IntoResponse;
    let store = store(&state)?;
    let source = state
        .key_service
        .as_ref()
        .ok_or(Refusal::KeyServiceUnavailable)?;
    store.begin_service_key_ask(&session).await?;
    let account = *session.account_id.as_bytes();
    let answer = source
        .create_or_get(account)
        .await
        .map_err(key_service_refusal)?;
    let (certification, statement_hash) = checked_certification(&answer, account)?;
    store
        .put_service_certification(session.account_id, &certification)
        .await?;
    // Whether a published head holds the entry yet: the create answer does not say.
    let covered = source
        .get(account)
        .await
        .map_err(key_service_refusal)?
        .and_then(|a| a.head_covers_entry)
        .unwrap_or(false);
    if !covered {
        return Ok((
            StatusCode::ACCEPTED,
            Json(wire::ApiError {
                code: "service_key_pending".to_owned(),
                message:
                    "The service key exists but the log does not hold it yet; ask again shortly."
                        .to_owned(),
            }),
        )
            .into_response());
    }
    Ok(Json(wire::ServiceKeyCertification {
        account_id: session.account_id.to_string(),
        identity_version: certification.identity_version,
        public_key: encode(&certification.public_key),
        statement_hash: encode(&statement_hash),
        signature: encode(&certification.signature),
        entry_index: answer.entry_index,
    })
    .into_response())
}

fn key_service_refusal(error: orbyn_keyservice_client::ClientError) -> Refusal {
    use orbyn_keyservice_client::ClientError;
    match error {
        ClientError::Retired => Refusal::ServiceKeyRetired,
        other => {
            // The kind only: nothing the service said is logged.
            tracing::warn!(kind = ?other, "the key service did not give a service key");
            Refusal::KeyServiceUnavailable
        }
    }
}

/// The certification in a key service answer, if the answer is for `account` and hangs together:
/// the fields have their lengths, the key is a P-256 point, and the statement rebuilt from the
/// account, the identity version and the key hashes to the hash the answer carries.
fn checked_certification(
    answer: &orbyn_keyservice_client::ServiceKeyAnswer,
    account: [u8; 16],
) -> Answer<(NewServiceCertification, [u8; 32])> {
    use orbyn_keyservice_client::{hex, unhex};
    let bad = || {
        tracing::warn!("the key service gave an answer that does not hang together");
        Refusal::KeyServiceUnavailable
    };
    if answer.account_id != hex(&account) || answer.identity_version == 0 {
        return Err(bad());
    }
    let public: [u8; 33] = unhex(&answer.public_key).ok_or_else(bad)?;
    let hash: [u8; 32] = unhex(&answer.statement_hash).ok_or_else(bad)?;
    let signature: [u8; 64] = unhex(&answer.signature).ok_or_else(bad)?;
    let point = orbyn_crypto::P256Point::parse(&public).map_err(|_| bad())?;
    let statement = orbyn_crypto::service_key_statement(answer.identity_version, &account, &point);
    if orbyn_crypto::service_key_statement_hash(&statement) != hash {
        return Err(bad());
    }
    Ok((
        NewServiceCertification {
            identity_version: answer.identity_version,
            public_key: public.to_vec(),
            statement,
            signature: signature.to_vec(),
        },
        hash,
    ))
}

/// `GET /v1/keychain/service-missing`: the zone keys to send service envelopes for.
async fn service_missing(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::ServiceMissingList>> {
    let keys = store(&state)?.service_missing(&session).await?;
    Ok(Json(wire::ServiceMissingList {
        keys: keys
            .into_iter()
            .map(|k| wire::MissingServiceKey {
                zone: k.zone,
                key_id: encode(&k.key_id),
            })
            .collect(),
    }))
}
