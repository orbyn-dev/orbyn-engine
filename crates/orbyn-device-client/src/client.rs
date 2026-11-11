//! The call sequences: sign-up, sign-in, re-login and sign-out. Passwords are only ever held in a
//! [`Zeroizing`] string, are turned into OPAQUE messages on this device and are never sent.

use crate::api::{DeviceApi, Method, Request, Response};
use crate::clock::Clock;
use crate::error::DeviceError;
use crate::store::{KeyStore, StoredIdentity, StoredSession};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use orbyn_auth_client as auth;
use orbyn_contracts as wire;
use orbyn_crypto::{DeviceKeys, DevicePublic};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::Duration;
use zeroize::Zeroizing;

/// A password. Wiped when dropped.
pub type Password = Zeroizing<String>;

/// What the host says about this device.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// A name the person chose for this device, 1 to 100 characters.
    pub device_name: String,
    pub platform: wire::DevicePlatform,
}

/// What a sign-up needs.
pub struct SignUpRequest {
    pub email: String,
    pub password: Password,
    /// The invite code, when the server asks for one.
    pub invite: Option<String>,
}

/// Who this device is signed in as. Never holds a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub account_id: String,
    pub device_id: String,
    pub email: String,
    pub device_state: wire::DeviceState,
}

/// A sign-in that waits for the second factor.
pub struct SecondFactorChallenge {
    login_id: String,
    email: String,
    keys: DeviceKeys,
}

impl std::fmt::Debug for SecondFactorChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecondFactorChallenge(..)")
    }
}

/// A code from the authenticator app, or one of the one-time recovery codes.
pub enum SecondFactor {
    Code(Zeroizing<String>),
    Recovery(Zeroizing<String>),
}

/// How a sign-in ended.
#[derive(Debug)]
pub enum SignInOutcome {
    /// Signed in on a trusted device.
    SignedIn(SessionInfo),
    /// Signed in, but this is a new device: a trusted device must approve it first.
    NeedsApproval(SessionInfo),
    /// The account has a second factor: pass this to [`DeviceClient::complete_second_factor`].
    SecondFactor(Box<SecondFactorChallenge>),
}

/// The device client: a transport, a key store and a clock.
pub struct DeviceClient<A, S, C> {
    pub(crate) api: A,
    pub(crate) store: S,
    pub(crate) clock: C,
    pub(crate) config: ClientConfig,
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub(crate) fn decode(text: &str) -> Result<Vec<u8>, DeviceError> {
    B64.decode(text).map_err(|_| protocol())
}

pub(crate) fn protocol() -> DeviceError {
    DeviceError::Server {
        status: 0,
        code: "bad_response".to_owned(),
    }
}

pub(crate) fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, DeviceError> {
    serde_json::to_vec(value).map_err(|_| DeviceError::Crypto)
}

pub(crate) fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, DeviceError> {
    serde_json::from_slice(body).map_err(|_| protocol())
}

/// An emailed code as people type it: spaces and hyphens ignored, any case.
pub(crate) fn normalise_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Turns a refusal into a typed error.
pub(crate) fn failure(response: &Response) -> DeviceError {
    let code = serde_json::from_slice::<wire::ApiError>(&response.body)
        .map(|e| e.code)
        .unwrap_or_default();
    match (response.status, code.as_str()) {
        (401, "reauthentication_required") => DeviceError::ReauthenticationRequired,
        (400, "invalid_email_code") => DeviceError::InvalidCode,
        (429, _) => DeviceError::RateLimited {
            retry_after: response.retry_after.map(Duration::from_secs),
        },
        (409, "deletion_scheduled") => DeviceError::DeletionScheduled,
        (413, _) => DeviceError::TooLarge,
        (401, "login_failed") => DeviceError::LoginFailed,
        (400, "invite_invalid") => DeviceError::InviteInvalid,
        (401, "second_factor_failed") => DeviceError::SecondFactorFailed,
        (403, "device_not_trusted") => DeviceError::DeviceNotTrusted,
        (401, "unauthorized") => DeviceError::SessionExpired,
        (status, _) => DeviceError::Server { status, code },
    }
}

pub(crate) fn is_ok(response: &Response) -> bool {
    (200..300).contains(&response.status)
}

impl<A: DeviceApi, S: KeyStore, C: Clock> DeviceClient<A, S, C> {
    pub fn new(api: A, store: S, clock: C, config: ClientConfig) -> Self {
        Self {
            api,
            store,
            clock,
            config,
        }
    }

    /// The key store, for the host.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Who this device is signed in as, from the key store.
    pub fn identity(&self) -> Result<Option<(String, String, String)>, DeviceError> {
        Ok(self
            .store
            .load()?
            .map(|i| (i.account_id, i.device_id, i.email)))
    }

    pub(crate) fn new_device(&self, keys: &DevicePublic) -> wire::NewDevice {
        wire::NewDevice {
            name: self.config.device_name.clone(),
            platform: self.config.platform,
            signing_key: encode(&keys.signing),
            agreement_key: encode(&keys.agreement),
        }
    }

    pub(crate) async fn call(
        &self,
        method: Method,
        path: &str,
        bearer: Option<Zeroizing<String>>,
        body: Option<Vec<u8>>,
    ) -> Result<Response, DeviceError> {
        self.api
            .send(Request {
                method,
                path: path.to_owned(),
                bearer,
                body,
            })
            .await
    }

    /// A call that must answer 2xx with a JSON body of type `R`.
    pub(crate) async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, DeviceError> {
        let response = self
            .call(Method::Post, path, None, Some(json(body)?))
            .await?;
        if !is_ok(&response) {
            return Err(failure(&response));
        }
        parse(&response.body)
    }

    /// An authenticated call with this device's session. A 401 asks the server whether the
    /// account still exists: [`DeviceError::AccountGone`] if it was deleted, else
    /// [`DeviceError::SessionExpired`].
    pub(crate) async fn authed(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Response, DeviceError> {
        let identity = self.store.load()?.ok_or(DeviceError::NotSignedIn)?;
        let session = identity.session.as_ref().ok_or(DeviceError::NotSignedIn)?;
        let response = self
            .call(method, path, Some(session.token.clone()), body)
            .await?;
        if is_ok(&response) {
            return Ok(response);
        }
        let error = failure(&response);
        if error == DeviceError::SessionExpired {
            let status: Result<wire::AccountStatus, _> = self
                .post(
                    "/v1/accounts/status",
                    &wire::AccountStatusRequest {
                        account_id: identity.account_id.clone(),
                    },
                )
                .await;
            if status.is_ok_and(|s| !s.deleted_at.is_empty()) {
                return Err(DeviceError::AccountGone);
            }
        }
        Err(error)
    }

    // ---- sign-in ----

    /// Signs in with the email and password. On a device this store already holds for the same
    /// account the start is signed with the device key (a trusted start), which skips the
    /// per-email limit and the second-factor code; any other device is new and is pending until a
    /// trusted device approves it. A store that holds another account's device is
    /// [`DeviceError::StoreNotEmpty`].
    pub async fn sign_in(
        &self,
        email: &str,
        password: &Password,
    ) -> Result<SignInOutcome, DeviceError> {
        let email = auth::normalize_email(email)
            .ok_or(DeviceError::InvalidInput("the email is not valid"))?;
        let existing = self.store.load()?;
        if existing.as_ref().is_some_and(|i| i.email != email) {
            return Err(DeviceError::StoreNotEmpty);
        }
        self.sign_in_with(&email, password, existing).await
    }

    /// The sign-in that answers [`DeviceError::ReauthenticationRequired`]: the same email, this
    /// device's key and the password again. It returns a new, recent session for the same device,
    /// with no approval; then send the refused request again.
    pub async fn reauthenticate(&self, password: &Password) -> Result<SessionInfo, DeviceError> {
        let identity = self.store.load()?.ok_or(DeviceError::NotSignedIn)?;
        let email = identity.email.clone();
        match self.sign_in_with(&email, password, Some(identity)).await? {
            SignInOutcome::SignedIn(info) | SignInOutcome::NeedsApproval(info) => Ok(info),
            // A trusted start skips the factor, so this is a device that is not trusted.
            SignInOutcome::SecondFactor(_) => Err(DeviceError::DeviceNotTrusted),
        }
    }

    async fn sign_in_with(
        &self,
        email: &str,
        password: &Password,
        existing: Option<StoredIdentity>,
    ) -> Result<SignInOutcome, DeviceError> {
        let (login, request) =
            auth::start_login(password.as_bytes()).map_err(|_| DeviceError::Crypto)?;
        let keys = match &existing {
            Some(identity) => identity.keys()?,
            None => DeviceKeys::generate().map_err(|_| DeviceError::Crypto)?,
        };
        let public = keys.public();
        let trusted_device = existing.as_ref().map(|_| {
            let signed_at = self.clock.now_secs();
            wire::TrustedDeviceProof {
                signing_key: encode(&public.signing),
                signed_at,
                signature: encode(&keys.sign(
                    auth::TRUSTED_START_CONTEXT,
                    &auth::trusted_start_message(email, &request, signed_at),
                )),
            }
        });
        let started: wire::LoginStarted = self
            .post(
                "/v1/sessions/login/start",
                &wire::LoginStart {
                    email: email.to_owned(),
                    credential_request: encode(&request),
                    trusted_device,
                },
            )
            .await?;
        // A wrong password fails here, on the device, and nothing more is sent.
        let finish = login
            .finish(password.as_bytes(), &decode(&started.credential_response)?)
            .map_err(|_| DeviceError::LoginFailed)?;
        let login_id: [u8; 16] = *uuid::Uuid::parse_str(&started.login_id)
            .map_err(|_| protocol())?
            .as_bytes();
        let signature = keys.sign(
            auth::DEVICE_LOGIN_CONTEXT,
            &auth::login_message(&login_id, &public),
        );
        let response = self
            .call(
                Method::Post,
                "/v1/sessions/login/finish",
                None,
                Some(json(&wire::LoginFinish {
                    login_id: started.login_id.clone(),
                    credential_finalization: encode(&finish.finalization),
                    device: self.new_device(&public),
                    device_signature: encode(&signature),
                })?),
            )
            .await?;
        if is_ok(&response) {
            let created: wire::SessionCreated = parse(&response.body)?;
            return self.finish_sign_in(&created, &keys, email, existing.as_ref());
        }
        if response.status == 401
            && let Ok(factor) = serde_json::from_slice::<wire::SecondFactorRequired>(&response.body)
            && factor.code == "second_factor_required"
        {
            return Ok(SignInOutcome::SecondFactor(Box::new(
                SecondFactorChallenge {
                    login_id: factor.login_id,
                    email: email.to_owned(),
                    keys,
                },
            )));
        }
        Err(failure(&response))
    }

    /// Finishes a sign-in that asked for the second factor. A wrong code is
    /// [`DeviceError::SecondFactorFailed`] and leaves the challenge usable (the server closes it
    /// after five).
    pub async fn complete_second_factor(
        &self,
        challenge: &SecondFactorChallenge,
        factor: SecondFactor,
    ) -> Result<SignInOutcome, DeviceError> {
        let (code, recovery_code) = match factor {
            SecondFactor::Code(code) => (Some(code.to_string()), None),
            SecondFactor::Recovery(code) => (None, Some(code.to_string())),
        };
        let created: wire::SessionCreated = self
            .post(
                "/v1/sessions/login/second-factor",
                &wire::SecondFactorLogin {
                    login_id: challenge.login_id.clone(),
                    code,
                    recovery_code,
                },
            )
            .await?;
        let existing = self.store.load()?;
        self.finish_sign_in(
            &created,
            &challenge.keys,
            &challenge.email,
            existing.as_ref(),
        )
    }

    fn finish_sign_in(
        &self,
        created: &wire::SessionCreated,
        keys: &DeviceKeys,
        email: &str,
        existing: Option<&StoredIdentity>,
    ) -> Result<SignInOutcome, DeviceError> {
        let info = self.save_session(created, keys, email, existing)?;
        Ok(match info.device_state {
            wire::DeviceState::Trusted => SignInOutcome::SignedIn(info),
            wire::DeviceState::Pending => SignInOutcome::NeedsApproval(info),
        })
    }

    /// Saves the device and its new session. The vault key is made once, on this device, and kept
    /// across sign-ins.
    pub(crate) fn save_session(
        &self,
        created: &wire::SessionCreated,
        keys: &DeviceKeys,
        email: &str,
        existing: Option<&StoredIdentity>,
    ) -> Result<SessionInfo, DeviceError> {
        let vault_key = match existing {
            Some(identity) => identity.vault_key.clone(),
            None => {
                let mut key = Zeroizing::new([0u8; 32]);
                getrandom::fill(key.as_mut_slice()).map_err(|_| DeviceError::Crypto)?;
                key
            }
        };
        self.store.save(&StoredIdentity {
            device_keys: keys.to_bytes(),
            account_id: created.account_id.clone(),
            device_id: created.device_id.clone(),
            email: email.to_owned(),
            session: Some(StoredSession {
                token: Zeroizing::new(created.token.clone()),
                expires_at: created.expires_at.clone(),
            }),
            vault_key,
        })?;
        Ok(SessionInfo {
            account_id: created.account_id.clone(),
            device_id: created.device_id.clone(),
            email: email.to_owned(),
            device_state: created.device_state,
        })
    }

    // ---- sign-out ----

    /// Signs this device out. The server is told when it can be (a failure to reach it does not
    /// stop the local sign-out). With `forget` the device keys and everything else are removed
    /// too, and the next sign-in is a new device that needs approval; without it the keys stay,
    /// so signing in again is the same device.
    pub async fn sign_out(&self, forget: bool) -> Result<(), DeviceError> {
        let Some(mut identity) = self.store.load()? else {
            return Ok(());
        };
        if let Some(session) = &identity.session {
            let _ = self
                .call(
                    Method::Delete,
                    "/v1/sessions/current",
                    Some(session.token.clone()),
                    None,
                )
                .await;
        }
        if forget {
            self.store.clear()?;
        } else {
            identity.session = None;
            self.store.save(&identity)?;
        }
        Ok(())
    }

    /// Signs every session of every device out, this one included. Needs a recent sign-in
    /// ([`DeviceError::ReauthenticationRequired`]; call [`DeviceClient::reauthenticate`] and try
    /// again). The device keys stay.
    pub async fn sign_out_all(&self) -> Result<(), DeviceError> {
        self.authed(Method::Delete, "/v1/sessions", None).await?;
        if let Some(mut identity) = self.store.load()? {
            identity.session = None;
            self.store.save(&identity)?;
        }
        Ok(())
    }
}
