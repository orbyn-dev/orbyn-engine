//! `/v1` routes for accounts, sessions and devices. Each route decodes the wire
//! types, calls one operation of `orbyn_core::Accounts`, and maps the result.

use crate::{AppState, error};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use orbyn_contracts as wire;
use orbyn_core::accounts::{self, AccountError};
use uuid::Uuid;

mod support;

use support::{Answer, bytes, fixed, id, new_device, wire_device, wire_session};
pub(crate) use support::{Authed, Body, Caller, encode, service, time};

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/accounts/register/start", post(register_start))
        .route("/v1/accounts/register/finish", post(register_finish))
        .route("/v1/invites/check", post(invite_check))
        .route("/v1/accounts/email/verify", post(email_verify))
        .route("/v1/accounts/email/resend", post(email_resend))
        .route("/v1/sessions/login/start", post(login_start))
        .route("/v1/sessions/login/finish", post(login_finish))
        .route(
            "/v1/sessions/login/second-factor",
            post(login_second_factor),
        )
        .route("/v1/accounts/totp", post(totp_enrol))
        .route("/v1/accounts/totp/confirm", post(totp_confirm))
        .route("/v1/accounts/totp/disable", post(totp_disable))
        .route("/v1/accounts/delete", post(delete_account))
        .route("/v1/accounts/delete/cancel", post(cancel_deletion))
        .route(
            "/v1/accounts/delete/cancel-by-mail",
            post(cancel_deletion_by_mail),
        )
        .route("/v1/accounts/status", post(account_status))
        .route("/v1/accounts/delete-unused", post(delete_unused_request))
        .route(
            "/v1/accounts/delete-unused/confirm",
            post(delete_unused_confirm),
        )
        .route("/v1/sessions/current", delete(revoke_current))
        .route("/v1/sessions", delete(revoke_all))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/current", get(current_device))
        .route(
            "/v1/devices/current/push-token",
            axum::routing::put(register_push_token).delete(remove_push_token),
        )
        .route("/v1/devices/approvals", post(create_approval))
        .route("/v1/devices/approvals/{id}", get(approval))
        .route("/v1/devices/approvals/{id}/nonce", post(submit_nonce))
        .route("/v1/devices/approvals/{id}/reveal", post(reveal_nonce))
        .route("/v1/devices/approvals/{id}/confirm", post(confirm_approval))
        .route("/v1/devices/approvals/{id}/cancel", post(cancel_approval))
        .route("/v1/devices/approvals/{id}/code", post(submit_code))
        .route("/v1/devices/{id}", delete(remove_device))
}

/// A failed request, as an [`wire::ApiError`] with a stable code.
async fn register_start(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::RegisterStart>,
) -> Answer<Json<wire::RegisterStarted>> {
    let response = service(&state)?
        .register_start(&client, &body.email, &bytes(&body.registration_request)?)
        .await?;
    Ok(Json(wire::RegisterStarted {
        registration_response: encode(&response),
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::RegisterFinish>,
) -> Answer<(StatusCode, Json<wire::SignUpPending>)> {
    let signup_id = service(&state)?
        .register_finish(
            &client,
            &body.email,
            &bytes(&body.registration_upload)?,
            &new_device(&body.device)?,
            &fixed(&body.device_signature)?,
            body.invite.as_deref(),
            body.proof.as_ref().map(|p| (p.challenge.as_str(), p.nonce)),
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(wire::SignUpPending {
            signup_id: signup_id.to_string(),
        }),
    ))
}

async fn invite_check(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::InviteCheck>,
) -> Answer<StatusCode> {
    service(&state)?
        .check_invite(&client, Some(&body.invite))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn email_verify(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::EmailVerify>,
) -> Answer<(StatusCode, Json<wire::SessionCreated>)> {
    // An id that is not even a UUID is a sign-up nobody made: the same refusal as any other.
    let signup_id = Uuid::parse_str(&body.signup_id).map_err(|_| AccountError::InvalidEmailCode)?;
    let session = service(&state)?
        .email_verify(&client, signup_id, &body.code)
        .await?;
    Ok((StatusCode::CREATED, Json(wire_session(session))))
}

async fn email_resend(
    State(state): State<AppState>,
    Body(body): Body<wire::EmailResend>,
) -> Answer<StatusCode> {
    if let Ok(signup_id) = Uuid::parse_str(&body.signup_id) {
        service(&state)?.email_resend(signup_id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn login_start(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::LoginStart>,
) -> Answer<Json<wire::LoginStarted>> {
    let trusted = match &body.trusted_device {
        Some(proof) => Some(orbyn_core::accounts::TrustedStart {
            signing_key: fixed(&proof.signing_key)?,
            signed_at: proof.signed_at,
            signature: fixed(&proof.signature)?,
        }),
        None => None,
    };
    let challenge = service(&state)?
        .login_start(
            &client,
            &body.email,
            &bytes(&body.credential_request)?,
            trusted.as_ref(),
        )
        .await?;
    Ok(Json(wire::LoginStarted {
        login_id: challenge.login_id.to_string(),
        credential_response: encode(&challenge.response),
    }))
}

async fn login_finish(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::LoginFinish>,
) -> Answer<Json<wire::SessionCreated>> {
    let session = service(&state)?
        .login_finish(
            &client,
            id(&body.login_id)?,
            &bytes(&body.credential_finalization)?,
            &new_device(&body.device)?,
            &fixed(&body.device_signature)?,
        )
        .await?;
    Ok(Json(wire_session(session)))
}

async fn revoke_current(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
) -> Answer<StatusCode> {
    service(&state)?.revoke_session(&client, &session).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_all(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
) -> Answer<StatusCode> {
    service(&state)?
        .revoke_all_sessions(&client, &session)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::DeviceList>> {
    let (devices, removals) = service(&state)?.list_devices(&session).await?;
    Ok(Json(wire::DeviceList {
        devices: devices
            .into_iter()
            .map(|d| wire_device(d, session.device_id))
            .collect(),
        removals: removals
            .into_iter()
            .map(|r| wire::DeviceRemoval {
                device_id: r.device_id.to_string(),
                signing_key: encode(&r.keys.signing),
                agreement_key: encode(&r.keys.agreement),
                removed_by: r.removed_by.to_string(),
                sequence: r.sequence,
                signature: encode(&r.signature),
            })
            .collect(),
    }))
}

async fn current_device(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::CurrentDevice>> {
    let accounts = service(&state)?;
    let (device, approval) = accounts.current_device(&session).await?;
    let (totp_enabled, totp_pending) = accounts.totp_status(session.account_id).await?;
    Ok(Json(wire::CurrentDevice {
        device: wire_device(device, session.device_id),
        approval: approval.map(wire_approval),
        totp_enabled,
        totp_pending,
        deletion_scheduled_at: accounts
            .deletion_scheduled_at(session.account_id)
            .await?
            .map(time),
    }))
}

fn wire_approval(a: accounts::ApprovalView) -> wire::PendingApproval {
    wire::PendingApproval {
        id: a.id.to_string(),
        expires_at: time(a.expires_at),
        created_at: a.created_at,
        approver_id: a.approver_id.to_string(),
        approver_signing_key: encode(&a.approver_keys.signing),
        approver_agreement_key: encode(&a.approver_keys.agreement),
        device_id: a.device_id.to_string(),
        device_signing_key: encode(&a.device_keys.signing),
        device_agreement_key: encode(&a.device_keys.agreement),
        commitment: encode(&a.commitment),
        device_nonce: a.device_nonce.map(|n| encode(&n)),
        approver_nonce: a.approver_nonce.map(|n| encode(&n)),
        signature: a.signature.map(|s| encode(&s)),
        endorsement: a.endorsement.as_deref().map(encode),
    }
}

async fn create_approval(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::CreateApproval>,
) -> Answer<(StatusCode, Json<wire::ApprovalCreated>)> {
    let approval = service(&state)?
        .create_approval(
            &client,
            &session,
            id(&body.device_id)?,
            id(&body.approval_id)?,
            body.created_at,
            &fixed(&body.commitment)?,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(wire::ApprovalCreated {
            id: approval.id.to_string(),
            expires_at: time(approval.expires_at),
        }),
    ))
}

async fn approval(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
) -> Answer<Json<wire::PendingApproval>> {
    let view = service(&state)?.approval(&session, id(&approval)?).await?;
    Ok(Json(wire_approval(view)))
}

async fn submit_nonce(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ApprovalNonce>,
) -> Answer<StatusCode> {
    service(&state)?
        .submit_device_nonce(&session, id(&approval)?, &fixed(&body.nonce)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reveal_nonce(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ApprovalNonce>,
) -> Answer<StatusCode> {
    service(&state)?
        .reveal_approver_nonce(&session, id(&approval)?, &fixed(&body.nonce)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn confirm_approval(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ConfirmApproval>,
) -> Answer<StatusCode> {
    let endorsement = body.endorsement.as_deref().map(bytes).transpose()?;
    service(&state)?
        .confirm_approval(
            &session,
            id(&approval)?,
            &fixed(&body.signature)?,
            endorsement.as_deref(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel_approval(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
) -> Answer<StatusCode> {
    service(&state)?
        .cancel_approval(&session, id(&approval)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn submit_code(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ApprovalCode>,
) -> Answer<Json<wire::Device>> {
    let device = service(&state)?
        .submit_approval_code(&client, &session, id(&approval)?, &body.code)
        .await?;
    Ok(Json(wire_device(device, session.device_id)))
}

async fn remove_device(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Path(device): Path<String>,
    Body(body): Body<wire::RemoveDevice>,
) -> Answer<StatusCode> {
    service(&state)?
        .remove_device(
            &client,
            &session,
            id(&device)?,
            body.sequence,
            &fixed(&body.signature)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn login_second_factor(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::SecondFactorLogin>,
) -> Answer<Json<wire::SessionCreated>> {
    let session = service(&state)?
        .login_second_factor(
            &client,
            id(&body.login_id)?,
            body.code.as_deref(),
            body.recovery_code.as_deref(),
        )
        .await?;
    Ok(Json(wire_session(session)))
}

async fn totp_enrol(
    State(state): State<AppState>,
    Authed(session): Authed,
    Body(body): Body<wire::TotpEnrol>,
) -> Answer<Json<wire::TotpEnrolment>> {
    let proof = manage_proof(body.device_signature.as_deref(), body.signed_at)?;
    let enrolment = service(&state)?
        .totp_enrol(&session, proof.as_ref())
        .await?;
    Ok(Json(wire::TotpEnrolment {
        secret: enrolment.secret.clone(),
        uri: enrolment.uri.clone(),
    }))
}

async fn totp_confirm(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::TotpConfirm>,
) -> Answer<Json<wire::TotpConfirmed>> {
    let proof = manage_proof(body.device_signature.as_deref(), body.signed_at)?;
    let recovery_codes = service(&state)?
        .totp_confirm(&client, &session, &body.code, proof.as_ref())
        .await?;
    Ok(Json(wire::TotpConfirmed { recovery_codes }))
}

async fn totp_disable(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::TotpDisable>,
) -> Answer<StatusCode> {
    let proof = manage_proof(body.device_signature.as_deref(), body.signed_at)?;
    service(&state)?
        .totp_disable(&client, &session, proof.as_ref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_account(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::DeleteAccount>,
) -> Answer<(StatusCode, Json<wire::DeletionScheduled>)> {
    let proof = manage_proof(body.device_signature.as_deref(), body.signed_at)?;
    let at = service(&state)?
        .schedule_deletion(
            &client,
            &session,
            body.code.as_deref(),
            body.recovery_code.as_deref(),
            proof.as_ref(),
        )
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(wire::DeletionScheduled {
            deletes_at: time(at),
        }),
    ))
}

async fn cancel_deletion(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::CancelAccountDeletion>,
) -> Answer<StatusCode> {
    let proof = manage_proof(body.device_signature.as_deref(), body.signed_at)?;
    service(&state)?
        .cancel_deletion(&client, &session, proof.as_ref())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel_deletion_by_mail(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::CancelDeletionByMail>,
) -> Answer<StatusCode> {
    service(&state)?
        .cancel_deletion_by_mail(&client, &body.token)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn register_push_token(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::PushTokenRequest>,
) -> Answer<StatusCode> {
    let provider = orbyn_core::push::PushProvider::parse(&body.provider)
        .ok_or(AccountError::InvalidRequest)?;
    service(&state)?
        .register_push_token(&client, &session, provider, &body.token)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_push_token(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
) -> Answer<StatusCode> {
    service(&state)?
        .remove_push_token(&client, &session)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Whether an account was deleted. A tombstone is 200 `{deleted_at}`; anything else is the same
/// 404, so a live account is not told apart from an id nobody used. Both answers are built the
/// same way, after the same single lookup.
async fn account_status(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::AccountStatusRequest>,
) -> Answer<Response> {
    let id = Uuid::parse_str(&body.account_id).map_err(|_| AccountError::InvalidRequest)?;
    let deleted = service(&state)?.deleted_on(&client, id).await?;
    let (status, code, deleted_at) = match deleted {
        Some(day) => (StatusCode::OK, "", Some(format!("{day}T00:00:00Z"))),
        None => (StatusCode::NOT_FOUND, "not_found", None),
    };
    Ok(match deleted_at {
        Some(deleted_at) => (status, Json(wire::AccountStatus { deleted_at })).into_response(),
        None => error(status, code, "There is no such item."),
    })
}

/// Always 202 `{}`: the service takes the same steps for every address and never reads the account.
async fn delete_unused_request(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::DeleteUnusedRequest>,
) -> Answer<(StatusCode, Json<serde_json::Value>)> {
    service(&state)?
        .request_delete_unused(&client, &body.email)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({}))))
}

async fn delete_unused_confirm(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::DeleteUnusedConfirm>,
) -> Answer<Json<wire::DeleteUnusedConfirmed>> {
    let invite_released = service(&state)?
        .confirm_delete_unused(&client, &body.token)
        .await?;
    Ok(Json(wire::DeleteUnusedConfirmed { invite_released }))
}

/// A missing signature is not a malformed request: it is a bearer token with no device behind it,
/// and the service answers it `device_proof_required`.
fn manage_proof(
    signature: Option<&str>,
    signed_at: Option<i64>,
) -> Answer<Option<accounts::ManageProof>> {
    let (Some(signature), Some(signed_at)) = (signature, signed_at) else {
        return Ok(None);
    };
    Ok(Some(accounts::ManageProof {
        signed_at,
        signature: fixed(signature)?,
    }))
}
