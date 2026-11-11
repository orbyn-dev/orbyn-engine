//! Sign-up: the OPAQUE steps, the proof of work and the emailed code.

use crate::api::Method;
use crate::client::{
    DeviceClient, SessionInfo, SignUpRequest, decode, encode, failure, is_ok, json, normalise_code,
    parse, protocol,
};
use crate::error::DeviceError;
use crate::{Clock, DeviceApi, KeyStore};
use orbyn_auth_client as auth;
use orbyn_contracts as wire;
use orbyn_crypto::{DeviceKeys, pow};

const MAX_PROOF_ROUNDS: usize = 2;

/// A sign-up that waits for the emailed code. It holds the new device's keys in memory only: an
/// abandoned sign-up leaves nothing behind. Drop it to cancel.
pub struct PendingSignUp {
    signup_id: String,
    email: String,
    keys: Option<DeviceKeys>,
}

impl PendingSignUp {
    pub fn email(&self) -> &str {
        &self.email
    }
}

impl std::fmt::Debug for PendingSignUp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingSignUp(..)")
    }
}

impl<A: DeviceApi, S: KeyStore, C: Clock> DeviceClient<A, S, C> {
    // ---- sign-up ----

    /// Starts a sign-up: the OPAQUE steps, this device's first signature, and the proof of work if
    /// the server asks for one (solved here, off the async threads). The server then emails a code
    /// to the address. Nothing is stored until [`DeviceClient::verify_sign_up`] succeeds.
    pub async fn begin_sign_up(
        &self,
        request: SignUpRequest,
    ) -> Result<PendingSignUp, DeviceError> {
        if self.store.load()?.is_some() {
            return Err(DeviceError::StoreNotEmpty);
        }
        let email = auth::normalize_email(&request.email)
            .ok_or(DeviceError::InvalidInput("the email is not valid"))?;
        if request.password.is_empty() {
            return Err(DeviceError::InvalidInput("the password is empty"));
        }
        let (registration, message) = auth::start_registration(request.password.as_bytes())
            .map_err(|_| DeviceError::Crypto)?;
        let started: wire::RegisterStarted = self
            .post(
                "/v1/accounts/register/start",
                &wire::RegisterStart {
                    email: email.clone(),
                    registration_request: encode(&message),
                },
            )
            .await?;
        let finish = registration
            .finish(
                request.password.as_bytes(),
                &decode(&started.registration_response)?,
            )
            .map_err(|_| DeviceError::Crypto)?;
        // The password is not needed again; wipe it now.
        drop(request.password);
        let keys = DeviceKeys::generate().map_err(|_| DeviceError::Crypto)?;
        let public = keys.public();
        let signature = keys.sign(
            auth::DEVICE_REGISTER_CONTEXT,
            &auth::register_message(&email, &finish.upload, &public),
        );
        let mut body = wire::RegisterFinish {
            email: email.clone(),
            registration_upload: encode(&finish.upload),
            device: self.new_device(&public),
            device_signature: encode(&signature),
            invite: request.invite,
            proof: None,
        };
        for round in 0..=MAX_PROOF_ROUNDS {
            let response = self
                .call(
                    Method::Post,
                    "/v1/accounts/register/finish",
                    None,
                    Some(json(&body)?),
                )
                .await?;
            if is_ok(&response) {
                let pending: wire::SignUpPending = parse(&response.body)?;
                return Ok(PendingSignUp {
                    signup_id: pending.signup_id,
                    email,
                    keys: Some(keys),
                });
            }
            if response.status != 428 || round == MAX_PROOF_ROUNDS {
                return Err(failure(&response));
            }
            let required: wire::ProofRequired = parse(&response.body)?;
            body.proof = Some(solve(required).await?);
        }
        Err(protocol())
    }

    /// Finishes a sign-up with the emailed code (any case, hyphen or not). A wrong code is
    /// [`DeviceError::InvalidCode`] and leaves the sign-up open: try again or ask for a new code.
    /// On success the keys, ids and session are saved and the account exists.
    pub async fn verify_sign_up(
        &self,
        pending: &mut PendingSignUp,
        code: &str,
    ) -> Result<SessionInfo, DeviceError> {
        let keys = pending
            .keys
            .as_ref()
            .ok_or(DeviceError::InvalidInput("this sign-up is finished"))?;
        let created: wire::SessionCreated = self
            .post(
                "/v1/accounts/email/verify",
                &wire::EmailVerify {
                    signup_id: pending.signup_id.clone(),
                    code: normalise_code(code),
                },
            )
            .await?;
        let info = self.save_session(&created, keys, &pending.email, None)?;
        pending.keys = None;
        Ok(info)
    }

    /// Asks for the code again (the server allows three an hour and answers the same whatever
    /// happens).
    pub async fn resend_sign_up(&self, pending: &PendingSignUp) -> Result<(), DeviceError> {
        let response = self
            .call(
                Method::Post,
                "/v1/accounts/email/resend",
                None,
                Some(json(&wire::EmailResend {
                    signup_id: pending.signup_id.clone(),
                })?),
            )
            .await?;
        if is_ok(&response) {
            Ok(())
        } else {
            Err(failure(&response))
        }
    }
}

/// Solves a proof-of-work challenge off the async threads, from a random start (the server takes
/// a solution once, so two starts must not find the same nonce).
async fn solve(required: wire::ProofRequired) -> Result<wire::SignupProof, DeviceError> {
    if required.bits > pow::MAX_BITS {
        return Err(DeviceError::Server {
            status: 428,
            code: required.code,
        });
    }
    let challenge = unhex(&required.challenge).ok_or_else(protocol)?;
    let mut start = [0u8; 4];
    getrandom::fill(&mut start).map_err(|_| DeviceError::Crypto)?;
    let bits = required.bits;
    let nonce = tokio::task::spawn_blocking(move || {
        pow::solve_from(&challenge, bits, u32::from_be_bytes(start))
    })
    .await
    .map_err(|_| DeviceError::Crypto)?
    .ok_or(DeviceError::Crypto)?;
    Ok(wire::SignupProof {
        challenge: required.challenge,
        nonce,
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}
