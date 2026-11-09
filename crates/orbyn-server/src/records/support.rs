//! Shared HTTP plumbing for the record routes: the waiting-slot accounting,
//! the refusal mapping, the body extractor and the wire conversions.

use super::{WAITING, WAITING_PER_ADDRESS};
use crate::accounts::{encode, time};
use crate::{AppState, error};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Json, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_contracts as wire;
use orbyn_store::{Change, Store, StoreError};
use serde::de::DeserializeOwned;

/// One address's waiting slot, given back when dropped.
pub(super) struct AddressSlot([u8; 16]);

impl AddressSlot {
    pub(super) fn take(ip: Option<std::net::IpAddr>) -> Option<Self> {
        let key = address_key(ip);
        // A poisoned lock still holds valid counts; never refuse forever.
        let mut guard = WAITING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let map = guard.get_or_insert_with(Default::default);
        let count = map.entry(key).or_insert(0);
        if *count >= WAITING_PER_ADDRESS {
            return None;
        }
        *count += 1;
        Some(Self(key))
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut guard = WAITING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(map) = guard.as_mut()
            && let Some(count) = map.get_mut(&self.0)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.0);
            }
        }
    }
}

/// An IPv4 address as is; an IPv6 address by its /64, as the sign-in limits count it.
pub(super) fn address_key(ip: Option<std::net::IpAddr>) -> [u8; 16] {
    match ip {
        Some(std::net::IpAddr::V4(v4)) => v4.to_ipv6_mapped().octets(),
        // An IPv4 client on a dual-stack socket or behind a proxy arrives as
        // ::ffff:a.b.c.d; count it as the IPv4 address it is.
        Some(std::net::IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some() => v6.octets(),
        Some(std::net::IpAddr::V6(v6)) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            o
        }
        None => [0; 16],
    }
}

/// A failed record request, as an [`wire::ApiError`] with a stable code.
pub(crate) enum Refusal {
    Store(StoreError),
    Unavailable,
    /// No key service is configured, or it cannot be reached or gave an answer that makes no sense.
    KeyServiceUnavailable,
    /// The account's service key was retired (Advanced): the key service makes no second key.
    ServiceKeyRetired,
    BadRequest,
    TooLarge,
}

impl From<StoreError> for Refusal {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let err = match self {
            Self::Unavailable => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "records_unavailable",
                    "The record store is not set up on this server.",
                );
            }
            Self::BadRequest => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The request is not valid.",
                );
            }
            Self::TooLarge => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "The request body is too large.",
                );
            }
            Self::KeyServiceUnavailable => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "key_service_unavailable",
                    "The key service is not available.",
                );
            }
            Self::ServiceKeyRetired => {
                return error(
                    StatusCode::CONFLICT,
                    "service_key_retired",
                    "The account's service key was retired.",
                );
            }
            Self::Store(err) => err,
        };
        let (status, code) = match &err {
            StoreError::InvalidZone => (StatusCode::BAD_REQUEST, "invalid_zone"),
            StoreError::InvalidRecord => (StatusCode::BAD_REQUEST, "invalid_record"),
            StoreError::RecordTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "record_too_large"),
            StoreError::BatchTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large"),
            StoreError::DuplicateRecord => (StatusCode::BAD_REQUEST, "duplicate_record"),
            StoreError::DeviceNotTrusted => (StatusCode::FORBIDDEN, "device_not_trusted"),
            StoreError::DeletionScheduled => (StatusCode::CONFLICT, "deletion_scheduled"),
            StoreError::ZoneNotFound => (StatusCode::NOT_FOUND, "zone_not_found"),
            StoreError::ZoneDeleted => (StatusCode::CONFLICT, "zone_deleted"),
            StoreError::ZonePurging => (StatusCode::CONFLICT, "zone_purging"),
            StoreError::InvalidToken => (StatusCode::BAD_REQUEST, "invalid_change_token"),
            StoreError::TokenExpired => (StatusCode::GONE, "token_expired"),
            StoreError::OperationReused => (StatusCode::CONFLICT, "operation_reused"),
            StoreError::TooManyZones => (StatusCode::UNPROCESSABLE_ENTITY, "too_many_zones"),
            StoreError::TooManyRecords => (StatusCode::UNPROCESSABLE_ENTITY, "too_many_records"),
            StoreError::InvalidEnvelope => (StatusCode::BAD_REQUEST, "invalid_envelope"),
            StoreError::RecipientNotTrusted => {
                (StatusCode::UNPROCESSABLE_ENTITY, "recipient_not_trusted")
            }
            StoreError::TooManyEnvelopes => {
                (StatusCode::UNPROCESSABLE_ENTITY, "too_many_envelopes")
            }
            StoreError::ServiceKeyChanged => (StatusCode::CONFLICT, "service_key_changed"),
            StoreError::ProtectionAdvanced => (StatusCode::CONFLICT, "protection_advanced"),
            StoreError::NoServiceKey => (StatusCode::CONFLICT, "service_key_missing"),
            StoreError::TooManyServiceKeyAsks => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_service_key_requests",
            ),
            StoreError::InvalidProtection => (StatusCode::BAD_REQUEST, "invalid_protection"),
            StoreError::InvalidProtectionSignature => {
                (StatusCode::BAD_REQUEST, "invalid_signature")
            }
            StoreError::TooManyProtectionChanges => {
                (StatusCode::TOO_MANY_REQUESTS, "too_many_changes")
            }
            StoreError::ProtectionConflict(head) => {
                let body = wire::ProtectionConflict {
                    code: "protection_conflict".to_owned(),
                    message: "The setting does not follow the current one.".to_owned(),
                    head: head.clone().map(|h| crate::keychain::wire_protection(*h)),
                };
                return (StatusCode::CONFLICT, Json(body)).into_response();
            }
            StoreError::TooManyUploads { retry_after } => {
                let mut response = error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_uploads",
                    "Too many uploads; try again shortly.",
                );
                response.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from(retry_after.as_secs().max(1)),
                );
                return response;
            }
            StoreError::TooManyConnections => {
                (StatusCode::TOO_MANY_REQUESTS, "too_many_connections")
            }
            StoreError::QuotaExceeded => (StatusCode::UNPROCESSABLE_ENTITY, "quota_exceeded"),
            StoreError::RecordChanged(conflicts) => {
                let body = wire::RecordChanged {
                    code: "record_changed".to_owned(),
                    message: "Records changed on the server; nothing was saved.".to_owned(),
                    conflicts: conflicts
                        .iter()
                        .map(|c| wire::RecordConflict {
                            record_id: c.record_id.clone(),
                            server_record: c.server_record.clone().map(wire_record),
                        })
                        .collect(),
                };
                return (StatusCode::CONFLICT, Json(body)).into_response();
            }
            StoreError::Database(db) => {
                let kind = match db {
                    orbyn_core::sqlx::Error::Database(e) => {
                        e.code().map(|c| c.into_owned()).unwrap_or_default()
                    }
                    other => format!("{:?}", std::mem::discriminant(other)),
                };
                tracing::error!(kind = %kind, "record store database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
            StoreError::Internal => {
                tracing::error!("record store internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "Something went wrong on the server.".to_owned()
        } else {
            let text = err.to_string();
            let mut chars = text.chars();
            match chars.next() {
                Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        };
        error(status, code, &message)
    }
}

pub(crate) type Answer<T> = Result<T, Refusal>;

/// A JSON body whose errors are [`wire::ApiError`]s, with this route's size limit.
pub(crate) struct Body<T>(pub(crate) T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = Refusal;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(Refusal::TooLarge)
            }
            Err(JsonRejection::BytesRejection(r))
                if r.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                Err(Refusal::TooLarge)
            }
            Err(_) => Err(Refusal::BadRequest),
        }
    }
}

pub(crate) fn store(state: &AppState) -> Answer<&Store> {
    state.store.as_ref().ok_or(Refusal::Unavailable)
}

pub(crate) fn bytes(text: &str) -> Answer<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Refusal::BadRequest)
}

pub(super) fn wire_zone(zone: orbyn_store::Zone) -> wire::Zone {
    wire::Zone {
        zone: zone.name,
        token: zone.token.encode(),
        deleted: zone.deleted,
        created_at: time(zone.created_at),
    }
}

pub(super) fn wire_record(record: orbyn_store::Record) -> wire::Record {
    wire::Record {
        record_id: record.record_id,
        record_type: record.record_type,
        version: record.version,
        ciphertext: record.ciphertext.as_deref().map(encode),
        wrapped_key: record.wrapped_key.as_deref().map(encode),
        author_device_id: record.author_device_id.to_string(),
        modified_at: time(record.modified_at),
        deleted: record.deleted,
        delete_proof: record.delete_proof.as_deref().map(encode),
    }
}

pub(super) fn change(change: wire::RecordChange) -> Answer<Change> {
    Ok(match change {
        wire::RecordChange::Save {
            record_id,
            record_type,
            expected_version,
            ciphertext,
            wrapped_key,
        } => Change::Save {
            record_id,
            record_type,
            expected_version,
            ciphertext: bytes(&ciphertext)?,
            wrapped_key: bytes(&wrapped_key)?,
        },
        wire::RecordChange::Delete {
            record_id,
            expected_version,
            proof,
        } => Change::Delete {
            record_id,
            expected_version,
            proof: proof.as_deref().map(bytes).transpose()?,
        },
    })
}
