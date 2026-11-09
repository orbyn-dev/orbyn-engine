//! Shared HTTP plumbing for the account routes: the failure mapping, the body
//! and caller extractors, and the wire conversions.

use crate::{AppState, error};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Json, Request};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat, Utc};
use orbyn_contracts as wire;
use orbyn_core::Accounts;
use orbyn_core::accounts::{self, AccountError, Client, Session};
use orbyn_crypto::DevicePublic;
use serde::de::DeserializeOwned;
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

pub(crate) enum Failure {
    Account(AccountError),
    Unavailable,
    BadRequest,
    TooLarge,
}

impl From<AccountError> for Failure {
    fn from(err: AccountError) -> Self {
        Self::Account(err)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let err = match self {
            Self::Unavailable => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "accounts_unavailable",
                    "Sign-in is not set up on this server.",
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
                    "The request body is larger than 64 KiB.",
                );
            }
            Self::Account(AccountError::ProofRequired { challenge, bits }) => {
                let body = wire::ProofRequired {
                    code: "proof_required".to_owned(),
                    message: "Too many sign-ups from here. Solve the proof of work and try again."
                        .to_owned(),
                    challenge,
                    bits,
                };
                return (StatusCode::PRECONDITION_REQUIRED, Json(body)).into_response();
            }
            Self::Account(AccountError::SecondFactorRequired { login_id }) => {
                let body = wire::SecondFactorRequired {
                    code: "second_factor_required".to_owned(),
                    message: "Send the code from your authenticator app to finish signing in."
                        .to_owned(),
                    login_id: login_id.to_string(),
                };
                return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
            }
            Self::Account(err) => err,
        };
        let (status, code) = match &err {
            AccountError::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            AccountError::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid_email"),
            AccountError::InvalidDeviceName => (StatusCode::BAD_REQUEST, "invalid_device_name"),
            AccountError::InvalidEmailCode => (StatusCode::BAD_REQUEST, "invalid_email_code"),
            AccountError::InviteInvalid => (StatusCode::BAD_REQUEST, "invite_invalid"),
            AccountError::LoginFailed => (StatusCode::UNAUTHORIZED, "login_failed"),
            AccountError::TooManyAttempts => (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
            // Answered above with its login id; never reached.
            AccountError::SecondFactorRequired { .. } => {
                (StatusCode::UNAUTHORIZED, "second_factor_required")
            }
            // Answered above with its challenge; never reached.
            AccountError::ProofRequired { .. } => {
                (StatusCode::PRECONDITION_REQUIRED, "proof_required")
            }
            AccountError::SecondFactorFailed => (StatusCode::UNAUTHORIZED, "second_factor_failed"),
            AccountError::ReauthenticationRequired => {
                (StatusCode::UNAUTHORIZED, "reauthentication_required")
            }
            AccountError::DeletionScheduled => (StatusCode::CONFLICT, "deletion_scheduled"),
            AccountError::InvalidCancelToken => (StatusCode::BAD_REQUEST, "invalid_cancel_token"),
            AccountError::InvalidDeleteUnusedToken => {
                (StatusCode::BAD_REQUEST, "invalid_delete_unused_token")
            }
            AccountError::DeleteUnusedNotPossible => {
                (StatusCode::CONFLICT, "delete_unused_not_possible")
            }
            AccountError::TotpAlreadyEnabled => (StatusCode::CONFLICT, "totp_already_enabled"),
            AccountError::TotpNotEnabled => (StatusCode::CONFLICT, "totp_not_enabled"),
            AccountError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AccountError::DeviceProofRequired => {
                (StatusCode::UNAUTHORIZED, "device_proof_required")
            }
            AccountError::DeviceNotTrusted => (StatusCode::FORBIDDEN, "device_not_trusted"),
            AccountError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AccountError::InvalidSignature => (StatusCode::BAD_REQUEST, "invalid_signature"),
            AccountError::WrongCode { remaining } => {
                let message = format!("The code is wrong. Attempts left: {remaining}.");
                return error(StatusCode::BAD_REQUEST, "wrong_code", &message);
            }
            AccountError::ApprovalExpired => (StatusCode::GONE, "approval_expired"),
            AccountError::ApprovalOutOfOrder => (StatusCode::CONFLICT, "approval_out_of_order"),
            AccountError::ApprovalNotConfirmed => (StatusCode::CONFLICT, "approval_not_confirmed"),
            AccountError::InvalidCommitment => (StatusCode::BAD_REQUEST, "invalid_commitment"),
            AccountError::DeviceKeyConflict => (StatusCode::CONFLICT, "device_key_conflict"),
            AccountError::LastTrustedDevice => (StatusCode::CONFLICT, "last_trusted_device"),
            AccountError::Database(db) => {
                // Postgres messages can quote values, such as an email in a
                // constraint error; log only the kind.
                let kind = match db {
                    orbyn_core::sqlx::Error::Database(e) => {
                        e.code().map(|c| c.into_owned()).unwrap_or_default()
                    }
                    other => format!("{:?}", std::mem::discriminant(other)),
                };
                tracing::error!(kind = %kind, "account database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
            AccountError::Internal => {
                tracing::error!("account internal error");
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

pub(super) type Answer<T> = Result<T, Failure>;

/// A JSON body whose errors are [`wire::ApiError`]s too.
pub(crate) struct Body<T>(pub(crate) T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = Failure;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(Failure::TooLarge)
            }
            Err(JsonRejection::BytesRejection(r))
                if r.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                Err(Failure::TooLarge)
            }
            Err(_) => Err(Failure::BadRequest),
        }
    }
}

pub(crate) fn service(state: &AppState) -> Answer<&Accounts> {
    state.accounts.as_ref().ok_or(Failure::Unavailable)
}

/// The caller's address, from the trusted proxy's header when one is set,
/// otherwise from the connection.
pub(crate) struct Caller(pub(crate) Client);

impl FromRequestParts<AppState> for Caller {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Failure> {
        let from_header = state.client_ip_header.as_ref().and_then(|name| {
            let found = parts
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.rsplit(',').next())
                .and_then(|last| last.trim().parse::<IpAddr>().ok());
            if found.is_none() {
                // Every such request falls back to the proxy's own address and
                // shares one limit bucket: say so once, so the setup is fixed.
                static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(header = %name, "the configured client address header is missing or not an address; using the connection's address");
                }
            }
            found
        });
        let ip = from_header.or_else(|| {
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip())
        });
        Ok(Self(Client { ip }))
    }
}

/// A valid `Authorization: Bearer` session.
pub(crate) struct Authed(pub(crate) Session);

impl FromRequestParts<AppState> for Authed {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Failure> {
        let accounts = service(state)?;
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                let (scheme, token) = v.split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then_some(token)
            })
            .ok_or(AccountError::Unauthorized)?;
        Ok(Self(accounts.authenticate(token).await?))
    }
}

pub(super) fn bytes(text: &str) -> Answer<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Failure::BadRequest)
}

pub(super) fn fixed<const N: usize>(text: &str) -> Answer<[u8; N]> {
    bytes(text)?.try_into().map_err(|_| Failure::BadRequest)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn id(text: &str) -> Answer<Uuid> {
    Uuid::parse_str(text).map_err(|_| Failure::BadRequest)
}

pub(crate) fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(super) fn platform(p: wire::DevicePlatform) -> accounts::Platform {
    use accounts::Platform as P;
    match p {
        wire::DevicePlatform::Web => P::Web,
        wire::DevicePlatform::Ios => P::Ios,
        wire::DevicePlatform::Android => P::Android,
        wire::DevicePlatform::Macos => P::Macos,
        wire::DevicePlatform::Windows => P::Windows,
        wire::DevicePlatform::Linux => P::Linux,
    }
}

pub(super) fn wire_platform(p: accounts::Platform) -> wire::DevicePlatform {
    use accounts::Platform as P;
    match p {
        P::Web => wire::DevicePlatform::Web,
        P::Ios => wire::DevicePlatform::Ios,
        P::Android => wire::DevicePlatform::Android,
        P::Macos => wire::DevicePlatform::Macos,
        P::Windows => wire::DevicePlatform::Windows,
        P::Linux => wire::DevicePlatform::Linux,
    }
}

pub(super) fn wire_state(s: accounts::DeviceState) -> wire::DeviceState {
    match s {
        accounts::DeviceState::Pending => wire::DeviceState::Pending,
        accounts::DeviceState::Trusted => wire::DeviceState::Trusted,
    }
}

pub(super) fn new_device(device: &wire::NewDevice) -> Answer<accounts::NewDevice> {
    Ok(accounts::NewDevice {
        name: device.name.clone(),
        platform: platform(device.platform),
        keys: DevicePublic {
            signing: fixed(&device.signing_key)?,
            agreement: fixed(&device.agreement_key)?,
        },
    })
}

pub(super) fn wire_device(device: accounts::Device, current: Uuid) -> wire::Device {
    wire::Device {
        id: device.id.to_string(),
        name: device.name,
        platform: wire_platform(device.platform),
        state: wire_state(device.state),
        signing_key: encode(&device.keys.signing),
        agreement_key: encode(&device.keys.agreement),
        created_at: time(device.created_at),
        approved_by: device.approved_by.map(|id| id.to_string()),
        approval_signature: device.approval_signature.map(|s| encode(&s)),
        approval_id: device.approval_id.map(|id| id.to_string()),
        approval_created_at: device.approval_created_at,
        approval_endorsement_hash: device.approval_endorsement_hash.map(|h| encode(&h)),
        current: device.id == current,
    }
}

pub(super) fn wire_session(session: accounts::NewSession) -> wire::SessionCreated {
    wire::SessionCreated {
        token: session.token.clone(),
        account_id: session.account_id.to_string(),
        device_id: session.device_id.to_string(),
        device_state: wire_state(session.device_state),
        expires_at: time(session.expires_at),
    }
}
