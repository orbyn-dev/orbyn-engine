//! A fake engine in memory: the same OPAQUE (real `opaque-ke` server side), the same signatures
//! and the same answers as the real server for sign-up, sign-in, the second factor and sign-out,
//! so the client is tested against the protocol and not against a stub of it.

use base64::Engine as _;
use orbyn_auth_client::opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use orbyn_auth_client::{
    DEVICE_LOGIN_CONTEXT, DEVICE_LOGIN_V2_CONTEXT, DEVICE_REGISTER_CONTEXT,
    DEVICE_REGISTER_V2_CONTEXT, Descriptor, LOGIN_CONTEXT, OsRng, Suite, TRUSTED_START_CONTEXT,
    login_message, login_message_v2, normalize_email, register_message, register_message_v2,
    trusted_start_message,
};
use orbyn_contracts as wire;
use orbyn_crypto::{DevicePublic, pow};
use orbyn_device_client::{DeviceApi, DeviceError, Method, Request, Response};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    B64.decode(text).expect("base64url")
}

fn key32(text: &str) -> [u8; 32] {
    unb64(text).try_into().expect("32 bytes")
}

pub struct Device {
    pub id: String,
    pub keys: DevicePublic,
    pub trusted: bool,
    /// The app label the device signed in, if it named one.
    pub app: Option<wire::DeviceApp>,
}

/// The descriptor a v2 message must cover: what the server would build from the request.
fn descriptor(device: &wire::NewDevice, app: wire::DeviceApp) -> Descriptor<'_> {
    Descriptor {
        name: device.name.trim(),
        platform: device.platform.as_str(),
        app: app.as_str(),
    }
}

pub struct Account {
    pub id: String,
    pub file: Vec<u8>,
    pub devices: Vec<Device>,
    /// The code the second factor accepts, when it is on.
    pub totp: Option<String>,
}

struct Pending {
    email: String,
    file: Vec<u8>,
    keys: DevicePublic,
    app: Option<wire::DeviceApp>,
    code: String,
    invite: Option<String>,
}

struct Login {
    state: ServerLogin<Suite>,
    email: String,
    trusted_signer: Option<[u8; 32]>,
}

struct SecondPending {
    account: String,
    device: String,
    attempts: u32,
}

pub struct Session {
    pub account: String,
    pub authenticated_at: i64,
}

struct State {
    setup: ServerSetup<Suite>,
    invites: HashSet<String>,
    accounts: HashMap<String, Account>,
    pending: HashMap<String, Pending>,
    logins: HashMap<String, Login>,
    second: HashMap<String, SecondPending>,
    sessions: HashMap<String, Session>,
    mail: Vec<(String, String)>,
    proof: Option<([u8; 32], u32)>,
    proofs_spent: HashSet<u32>,
    register_limit: Option<u64>,
    deleted: HashSet<String>,
    status_mode: StatusMode,
    counter: u64,
    log: Vec<(String, String)>,
}

/// How `POST /v1/accounts/status` behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StatusMode {
    Normal,
    /// Answers 500.
    ServerError,
    /// Answers nothing: a transport failure.
    Unreachable,
}

/// The fake. Cloning shares the one server.
#[derive(Clone)]
pub struct FakeEngine {
    state: Arc<Mutex<State>>,
    pub now: Arc<AtomicI64>,
}

fn answer(status: u16, body: Value) -> Result<Response, DeviceError> {
    Ok(Response {
        status,
        retry_after: None,
        body: Zeroizing::new(serde_json::to_vec(&body).expect("json")),
    })
}

fn error(status: u16, code: &str) -> Result<Response, DeviceError> {
    answer(status, json!({ "code": code, "message": code }))
}

impl FakeEngine {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                setup: ServerSetup::<Suite>::new(&mut OsRng),
                invites: HashSet::new(),
                accounts: HashMap::new(),
                pending: HashMap::new(),
                logins: HashMap::new(),
                second: HashMap::new(),
                sessions: HashMap::new(),
                mail: Vec::new(),
                proof: None,
                proofs_spent: HashSet::new(),
                register_limit: None,
                deleted: HashSet::new(),
                status_mode: StatusMode::Normal,
                counter: 0,
                log: Vec::new(),
            })),
            now: Arc::new(AtomicI64::new(1_800_000_000)),
        }
    }

    pub fn add_invite(&self, code: &str) {
        self.state
            .lock()
            .expect("lock")
            .invites
            .insert(code.to_owned());
    }

    /// Asks for a proof of work of `bits` bits on `register/finish`.
    pub fn require_proof(&self, bits: u32) {
        self.state.lock().expect("lock").proof = Some(([7u8; 32], bits));
    }

    /// Answers 429 with this `Retry-After` to every `register/start`.
    pub fn limit_register(&self, retry_after: u64) {
        self.state.lock().expect("lock").register_limit = Some(retry_after);
    }

    /// The newest code mailed to `email`.
    pub fn code_for(&self, email: &str) -> String {
        let s = self.state.lock().expect("lock");
        s.mail
            .iter()
            .rev()
            .find(|(to, _)| to == email)
            .map(|(_, code)| code.clone())
            .expect("a mail")
    }

    pub fn set_totp(&self, email: &str, code: &str) {
        let mut s = self.state.lock().expect("lock");
        s.accounts.get_mut(email).expect("account").totp = Some(code.to_owned());
    }

    pub fn delete_account(&self, email: &str) {
        let mut s = self.state.lock().expect("lock");
        let id = s.accounts.remove(email).expect("account").id;
        s.sessions.retain(|_, v| v.account != id);
        s.deleted.insert(id);
    }

    /// Ends every session of the account elsewhere; the account stays.
    pub fn revoke_sessions(&self, email: &str) {
        let mut s = self.state.lock().expect("lock");
        let id = s.accounts[email].id.clone();
        s.sessions.retain(|_, v| v.account != id);
    }

    pub fn status_mode(&self, mode: StatusMode) {
        self.state.lock().expect("lock").status_mode = mode;
    }

    pub fn advance(&self, secs: i64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn device_count(&self, email: &str) -> usize {
        self.state.lock().expect("lock").accounts[email]
            .devices
            .len()
    }

    /// The app label each device of the account signed, in the order they joined.
    pub fn device_apps(&self, email: &str) -> Vec<Option<wire::DeviceApp>> {
        self.state.lock().expect("lock").accounts[email]
            .devices
            .iter()
            .map(|d| d.app)
            .collect()
    }

    /// Every request body the fake has seen, as `(path, body text)`.
    pub fn log(&self) -> Vec<(String, String)> {
        self.state.lock().expect("lock").log.clone()
    }

    pub fn clear_log(&self) {
        self.state.lock().expect("lock").log.clear();
    }

    fn handle(&self, request: Request) -> Result<Response, DeviceError> {
        let mut s = self.state.lock().expect("lock");
        let body: Value = request
            .body
            .as_deref()
            .map(|b| serde_json::from_slice(b).expect("json body"))
            .unwrap_or(Value::Null);
        s.log.push((
            format!("{:?} {}", request.method, request.path),
            body.to_string(),
        ));
        let now = self.now.load(Ordering::SeqCst);
        let token = request.bearer.as_ref().map(|t| t.to_string());
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v1/accounts/register/start") => register_start(&mut s, &body),
            (Method::Post, "/v1/accounts/register/finish") => register_finish(&mut s, body),
            (Method::Post, "/v1/invites/check") => {
                // As the server: any code is fine when invites are not asked for; else a known,
                // unused one (ignoring case, spaces and hyphens).
                let code = body["invite"]
                    .as_str()
                    .unwrap_or_default()
                    .replace(['-', ' '], "")
                    .to_uppercase();
                if s.invites.is_empty() || s.invites.contains(&code) {
                    answer(204, Value::Null)
                } else {
                    error(400, "invite_invalid")
                }
            }
            (Method::Post, "/v1/accounts/email/verify") => email_verify(&mut s, &body, now),
            (Method::Post, "/v1/accounts/email/resend") => answer(204, Value::Null),
            (Method::Post, "/v1/sessions/login/start") => login_start(&mut s, &body, now),
            (Method::Post, "/v1/sessions/login/finish") => login_finish(&mut s, &body, now),
            (Method::Post, "/v1/sessions/login/second-factor") => second_factor(&mut s, &body, now),
            (Method::Post, "/v1/accounts/status") => {
                match s.status_mode {
                    StatusMode::ServerError => return error(500, "internal"),
                    StatusMode::Unreachable => return Err(DeviceError::Transport),
                    StatusMode::Normal => {}
                }
                let id = body["account_id"].as_str().unwrap_or_default();
                let deleted = if s.deleted.contains(id) {
                    "2026-11-12T00:00:00Z"
                } else {
                    ""
                };
                answer(200, json!({ "deleted_at": deleted }))
            }
            (Method::Delete, "/v1/sessions/current") => {
                let Some(session) = token.and_then(|t| s.sessions.remove(&t)) else {
                    return error(401, "unauthorized");
                };
                let _ = session;
                answer(204, Value::Null)
            }
            (Method::Delete, "/v1/sessions") => {
                let Some(session) = token.as_ref().and_then(|t| s.sessions.get(t)) else {
                    return error(401, "unauthorized");
                };
                if now - session.authenticated_at > 600 {
                    return error(401, "reauthentication_required");
                }
                let account = session.account.clone();
                s.sessions.retain(|_, v| v.account != account);
                answer(204, Value::Null)
            }
            _ => error(404, "not_found"),
        }
    }
}

impl DeviceApi for FakeEngine {
    async fn send(&self, request: Request) -> Result<Response, DeviceError> {
        self.handle(request)
    }
}

fn register_start(s: &mut State, body: &Value) -> Result<Response, DeviceError> {
    if let Some(after) = s.register_limit {
        return Ok(Response {
            status: 429,
            retry_after: Some(after),
            body: Zeroizing::new(
                serde_json::to_vec(&json!({"code": "too_many_attempts", "message": "x"}))
                    .expect("json"),
            ),
        });
    }
    let email = normalize_email(body["email"].as_str().unwrap_or_default()).expect("email");
    let request = RegistrationRequest::<Suite>::deserialize(&unb64(
        body["registration_request"].as_str().expect("request"),
    ))
    .expect("registration request");
    let start =
        ServerRegistration::<Suite>::start(&s.setup, request, email.as_bytes()).expect("start");
    answer(
        200,
        json!({ "registration_response": b64(&start.message.serialize()) }),
    )
}

fn register_finish(s: &mut State, body: Value) -> Result<Response, DeviceError> {
    let finish: wire::RegisterFinish = serde_json::from_value(body).expect("register finish");
    let email = normalize_email(&finish.email).expect("email");
    // The invite is judged first, as the server does.
    let invite = finish
        .invite
        .as_ref()
        .map(|i| i.replace(['-', ' '], "").to_uppercase());
    if !s.invites.is_empty() && !invite.as_ref().is_some_and(|i| s.invites.contains(i)) {
        return error(400, "invite_invalid");
    }
    let upload = unb64(&finish.registration_upload);
    let keys = DevicePublic {
        signing: key32(&finish.device.signing_key),
        agreement: key32(&finish.device.agreement_key),
    };
    let signature: [u8; 64] = unb64(&finish.device_signature)
        .try_into()
        .expect("signature");
    let (context, message) = match finish.device.app {
        Some(app) => (
            DEVICE_REGISTER_V2_CONTEXT,
            register_message_v2(&email, &upload, &keys, &descriptor(&finish.device, app)),
        ),
        None => (
            DEVICE_REGISTER_CONTEXT,
            register_message(&email, &upload, &keys),
        ),
    };
    orbyn_crypto::verify(&keys, context, &message, &signature)
        .expect("the device signed the registration");
    if let Some((challenge, bits)) = s.proof {
        let solved = finish.proof.as_ref().is_some_and(|p| {
            p.challenge == hex(&challenge)
                && pow::verify(&challenge, p.nonce, bits)
                && !s.proofs_spent.contains(&p.nonce)
        });
        if !solved {
            return answer(
                428,
                json!({"code": "proof_required", "message": "x", "challenge": hex(&challenge), "bits": bits}),
            );
        }
        s.proofs_spent.insert(finish.proof.expect("proof").nonce);
    }
    let file = ServerRegistration::<Suite>::finish(
        RegistrationUpload::<Suite>::deserialize(&upload).expect("upload"),
    )
    .serialize()
    .to_vec();
    s.counter += 1;
    let code = format!("{:08}", 23_456_789 + s.counter)
        .replace('0', "2")
        .replace('1', "3");
    let signup_id = format!("00000000-0000-4000-8000-{:012}", s.counter);
    s.mail.push((email.clone(), code.clone()));
    s.pending.insert(
        signup_id.clone(),
        Pending {
            email,
            file,
            keys,
            app: finish.device.app,
            code,
            invite,
        },
    );
    answer(201, json!({ "signup_id": signup_id }))
}

fn email_verify(s: &mut State, body: &Value, now: i64) -> Result<Response, DeviceError> {
    let id = body["signup_id"].as_str().unwrap_or_default();
    let code = body["code"].as_str().unwrap_or_default();
    let Some(pending) = s.pending.get(id) else {
        return error(400, "invalid_email_code");
    };
    if pending.code != code {
        return error(400, "invalid_email_code");
    }
    let pending = s.pending.remove(id).expect("pending");
    if let Some(invite) = &pending.invite {
        s.invites.remove(invite);
    }
    s.counter += 1;
    let account_id = format!("00000000-0000-4000-9000-{:012}", s.counter);
    let device_id = format!("00000000-0000-4000-a000-{:012}", s.counter);
    s.accounts.insert(
        pending.email.clone(),
        Account {
            id: account_id.clone(),
            file: pending.file,
            devices: vec![Device {
                id: device_id.clone(),
                keys: pending.keys,
                trusted: true,
                app: pending.app,
            }],
            totp: None,
        },
    );
    session(s, &account_id, &device_id, true, now, 201)
}

fn session(
    s: &mut State,
    account: &str,
    device: &str,
    trusted: bool,
    now: i64,
    status: u16,
) -> Result<Response, DeviceError> {
    s.counter += 1;
    let token = format!("token-{}", s.counter);
    s.sessions.insert(
        token.clone(),
        Session {
            account: account.to_owned(),
            authenticated_at: now,
        },
    );
    answer(
        status,
        json!({
            "token": token,
            "account_id": account,
            "device_id": device,
            "device_state": if trusted { "trusted" } else { "pending" },
            "expires_at": "2027-11-12T00:00:00Z",
        }),
    )
}

fn login_start(s: &mut State, body: &Value, now: i64) -> Result<Response, DeviceError> {
    let email = normalize_email(body["email"].as_str().unwrap_or_default()).expect("email");
    let request_bytes = unb64(body["credential_request"].as_str().expect("request"));
    let request = CredentialRequest::<Suite>::deserialize(&request_bytes).expect("request");
    let file = s
        .accounts
        .get(&email)
        .map(|a| ServerRegistration::<Suite>::deserialize(&a.file).expect("file"));
    // A trusted start: a fresh signature, by a device the account trusts, over this very request.
    let mut trusted_signer = None;
    if let Some(proof) = body.get("trusted_device").filter(|p| !p.is_null()) {
        let signing = key32(proof["signing_key"].as_str().expect("key"));
        let signed_at = proof["signed_at"].as_i64().expect("time");
        let signature: [u8; 64] = unb64(proof["signature"].as_str().expect("sig"))
            .try_into()
            .expect("sig");
        let known = s.accounts.get(&email).is_some_and(|a| {
            a.devices
                .iter()
                .any(|d| d.trusted && d.keys.signing == signing)
        });
        let signer = DevicePublic {
            signing,
            agreement: [0; 32],
        };
        if known
            && (now - signed_at).abs() <= 300
            && orbyn_crypto::verify(
                &signer,
                TRUSTED_START_CONTEXT,
                &trusted_start_message(&email, &request_bytes, signed_at),
                &signature,
            )
            .is_ok()
        {
            trusted_signer = Some(signing);
        }
    }
    let start = ServerLogin::start(
        &mut OsRng,
        &s.setup,
        file,
        request,
        email.as_bytes(),
        ServerLoginParameters {
            context: Some(LOGIN_CONTEXT),
            ..ServerLoginParameters::default()
        },
    )
    .expect("login start");
    s.counter += 1;
    let login_id = format!("00000000-0000-4000-b000-{:012}", s.counter);
    s.logins.insert(
        login_id.clone(),
        Login {
            state: start.state,
            email,
            trusted_signer,
        },
    );
    answer(
        200,
        json!({ "login_id": login_id, "credential_response": b64(&start.message.serialize()) }),
    )
}

fn login_finish(s: &mut State, body: &Value, now: i64) -> Result<Response, DeviceError> {
    let finish: wire::LoginFinish = serde_json::from_value(body.clone()).expect("login finish");
    let Some(login) = s.logins.remove(&finish.login_id) else {
        return error(401, "login_failed");
    };
    let verified = login
        .state
        .finish(
            CredentialFinalization::<Suite>::deserialize(&unb64(&finish.credential_finalization))
                .expect("finalization"),
            ServerLoginParameters {
                context: Some(LOGIN_CONTEXT),
                ..ServerLoginParameters::default()
            },
        )
        .is_ok();
    if !verified || !s.accounts.contains_key(&login.email) {
        return error(401, "login_failed");
    }
    let keys = DevicePublic {
        signing: key32(&finish.device.signing_key),
        agreement: key32(&finish.device.agreement_key),
    };
    let login_id: [u8; 16] = *uuid::Uuid::parse_str(&finish.login_id)
        .expect("uuid")
        .as_bytes();
    let signature: [u8; 64] = unb64(&finish.device_signature)
        .try_into()
        .expect("signature");
    let (context, message) = match finish.device.app {
        Some(app) => (
            DEVICE_LOGIN_V2_CONTEXT,
            login_message_v2(&login_id, &keys, &descriptor(&finish.device, app)),
        ),
        None => (DEVICE_LOGIN_CONTEXT, login_message(&login_id, &keys)),
    };
    orbyn_crypto::verify(&keys, context, &message, &signature)
        .expect("the device signed the login");
    let account = s.accounts.get_mut(&login.email).expect("account");
    let existing = account.devices.iter().position(|d| d.keys == keys);
    let (device_id, trusted) = match existing {
        Some(i) => (account.devices[i].id.clone(), account.devices[i].trusted),
        None => {
            let id = format!(
                "00000000-0000-4000-c000-{:012}",
                account.devices.len() + 1 + s.counter as usize
            );
            account.devices.push(Device {
                id: id.clone(),
                keys,
                trusted: false,
                app: finish.device.app,
            });
            (id, false)
        }
    };
    let skips = trusted && login.trusted_signer == Some(keys.signing);
    let account_id = account.id.clone();
    if account.totp.is_some() && !skips {
        s.counter += 1;
        let second_id = format!("00000000-0000-4000-d000-{:012}", s.counter);
        s.second.insert(
            second_id.clone(),
            SecondPending {
                account: login.email,
                device: device_id,
                attempts: 0,
            },
        );
        return answer(
            401,
            json!({"code": "second_factor_required", "message": "x", "login_id": second_id}),
        );
    }
    session(s, &account_id, &device_id, trusted, now, 200)
}

fn second_factor(s: &mut State, body: &Value, now: i64) -> Result<Response, DeviceError> {
    let id = body["login_id"].as_str().unwrap_or_default().to_owned();
    let Some(pending) = s.second.get_mut(&id) else {
        return error(401, "login_failed");
    };
    let email = pending.account.clone();
    let device = pending.device.clone();
    let right = s.accounts[&email].totp.as_deref() == body["code"].as_str();
    if !right {
        let pending = s.second.get_mut(&id).expect("pending");
        pending.attempts += 1;
        if pending.attempts >= 5 {
            s.second.remove(&id);
            return error(401, "login_failed");
        }
        return error(401, "second_factor_failed");
    }
    s.second.remove(&id);
    let account = &s.accounts[&email];
    let trusted = account
        .devices
        .iter()
        .find(|d| d.id == device)
        .is_some_and(|d| d.trusted);
    let account_id = account.id.clone();
    session(s, &account_id, &device, trusted, now, 200)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
