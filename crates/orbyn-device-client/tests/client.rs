//! The device client against an in-memory engine that speaks the real OPAQUE and checks the real
//! signatures (`tests/support`).

mod support;

use orbyn_contracts::{DeviceApp, DevicePlatform, DeviceState};
use orbyn_device_client::{
    ClientConfig, Clock, DeviceApi, DeviceClient, DeviceError, HttpApi, KeyStore, MemoryStore,
    Method, Password, Request, Response, SecondFactor, SignInOutcome, SignUpRequest, StoreError,
    StoredIdentity,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use support::{FakeEngine, StatusMode};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "Walker@Example.com ";
const NORMAL: &str = "walker@example.com";

struct SharedClock(Arc<AtomicI64>);

impl Clock for SharedClock {
    fn now_secs(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

type Client = DeviceClient<FakeEngine, MemoryStore, SharedClock>;

fn client(engine: &FakeEngine, name: &str) -> Client {
    DeviceClient::new(
        engine.clone(),
        MemoryStore::new(),
        SharedClock(engine.now.clone()),
        ClientConfig {
            device_name: name.to_owned(),
            platform: DevicePlatform::Linux,
            app: Some(DeviceApp::Engineering),
        },
    )
}

fn password(text: &str) -> Password {
    Password::new(text)
}

fn request(invite: Option<&str>) -> SignUpRequest {
    SignUpRequest {
        email: EMAIL.to_owned(),
        password: password(PASSWORD),
        invite: invite.map(str::to_owned),
    }
}

/// Signs the first device up and returns its client.
async fn first_device(engine: &FakeEngine) -> Client {
    let a = client(engine, "Laptop");
    let mut pending = a.begin_sign_up(request(None)).await.expect("begin");
    let code = engine.code_for(NORMAL);
    a.verify_sign_up(&mut pending, &code).await.expect("verify");
    a
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_up_runs_the_invite_the_proof_of_work_and_the_emailed_code() {
    let engine = FakeEngine::new();
    engine.add_invite("ABCD1234");
    engine.require_proof(10);
    let a = client(&engine, "Laptop");
    let mut pending = a
        .begin_sign_up(request(Some("abcd-1234")))
        .await
        .expect("a sign-up with a proof of work solved inside");
    assert_eq!(pending.email(), NORMAL, "the email is normalised");
    assert_eq!(a.identity().expect("store"), None, "nothing is kept yet");
    // Register/finish was sent twice: refused with a challenge, then with the solution.
    let finishes = engine
        .log()
        .iter()
        .filter(|(path, _)| path.ends_with("register/finish"))
        .count();
    assert_eq!(finishes, 2);

    // A wrong code leaves the sign-up open; the right one, typed with a hyphen, finishes it.
    assert_eq!(
        a.verify_sign_up(&mut pending, "00000000").await.err(),
        Some(DeviceError::InvalidCode)
    );
    let code = engine.code_for(NORMAL);
    let typed = format!("{}-{}", &code[..4], &code[4..]);
    let session = a
        .verify_sign_up(&mut pending, &typed)
        .await
        .expect("verify");
    assert_eq!(session.device_state, DeviceState::Trusted);
    let (account, device, email) = a.identity().expect("store").expect("saved");
    assert_eq!(
        (account, device, email),
        (session.account_id, session.device_id, NORMAL.to_owned())
    );
    assert_eq!(engine.device_count(NORMAL), 1);

    // The password never went anywhere: not in any body, not as base64.
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(PASSWORD);
    for (path, body) in engine.log() {
        assert!(
            !body.contains(PASSWORD) && !body.contains(&encoded),
            "{path}"
        );
    }
    // A second finish of the same sign-up is refused.
    assert!(a.verify_sign_up(&mut pending, &code).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_that_is_missing_or_wrong_is_refused() {
    let engine = FakeEngine::new();
    engine.add_invite("ABCD1234");
    for invite in [None, Some("WRONG-CODE")] {
        let a = client(&engine, "Laptop");
        assert_eq!(
            a.begin_sign_up(request(invite)).await.err(),
            Some(DeviceError::InviteInvalid)
        );
        assert_eq!(a.identity().expect("store"), None);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_device_signs_in_pending_and_a_trusted_one_signs_the_start() {
    let engine = FakeEngine::new();
    let a = first_device(&engine).await;
    let b = client(&engine, "Phone");
    engine.clear_log();
    let outcome = b
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("sign in");
    let SignInOutcome::NeedsApproval(info) = outcome else {
        panic!("a new device waits for approval: {outcome:?}");
    };
    assert_eq!(info.device_state, DeviceState::Pending);
    assert_eq!(engine.device_count(NORMAL), 2);
    let start = engine
        .log()
        .into_iter()
        .find(|(p, _)| p.ends_with("login/start"))
        .expect("start")
        .1;
    assert!(
        start.contains("\"trusted_device\":null"),
        "a new device sends no trusted start: {start}"
    );

    // The first device signs in again as itself: the start is signed, no new device appears.
    engine.clear_log();
    let outcome = a
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("sign in");
    assert!(matches!(outcome, SignInOutcome::SignedIn(_)), "{outcome:?}");
    assert_eq!(engine.device_count(NORMAL), 2);
    let start = engine
        .log()
        .into_iter()
        .find(|(p, _)| p.ends_with("login/start"))
        .expect("start")
        .1;
    assert!(
        start.contains("\"signing_key\""),
        "a trusted start is signed: {start}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_fails_on_the_device_and_sends_nothing_more() {
    let engine = FakeEngine::new();
    let _a = first_device(&engine).await;
    let b = client(&engine, "Phone");
    engine.clear_log();
    assert_eq!(
        b.sign_in(NORMAL, &password("wrong horse")).await.err(),
        Some(DeviceError::LoginFailed)
    );
    assert!(
        engine
            .log()
            .iter()
            .all(|(path, _)| !path.ends_with("login/finish"))
    );
    assert_eq!(b.identity().expect("store"), None);
    assert_eq!(engine.device_count(NORMAL), 1, "no device was added");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_second_factor_is_asked_of_a_new_device_and_skipped_by_a_trusted_start() {
    let engine = FakeEngine::new();
    let a = first_device(&engine).await;
    engine.set_totp(NORMAL, "123456");
    let b = client(&engine, "Phone");
    let outcome = b
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("sign in");
    let SignInOutcome::SecondFactor(challenge) = outcome else {
        panic!("the factor is asked: {outcome:?}");
    };
    assert_eq!(
        b.identity().expect("store"),
        None,
        "nothing is kept before the factor"
    );
    assert_eq!(
        b.complete_second_factor(
            &challenge,
            SecondFactor::Code(Zeroizing::new("000000".to_owned()))
        )
        .await
        .err(),
        Some(DeviceError::SecondFactorFailed)
    );
    let outcome = b
        .complete_second_factor(
            &challenge,
            SecondFactor::Code(Zeroizing::new("123456".to_owned())),
        )
        .await
        .expect("the right code");
    assert!(
        matches!(outcome, SignInOutcome::NeedsApproval(_)),
        "{outcome:?}"
    );
    assert!(b.identity().expect("store").is_some());
    // The trusted first device needs no code.
    let outcome = a
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("sign in");
    assert!(matches!(outcome, SignInOutcome::SignedIn(_)), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn signing_out_everywhere_needs_a_recent_sign_in_and_reauthenticate_gives_one() {
    let engine = FakeEngine::new();
    let a = first_device(&engine).await;
    let (_, device_before, _) = a.identity().expect("store").expect("saved");
    engine.advance(11 * 60);
    assert_eq!(
        a.sign_out_all().await.err(),
        Some(DeviceError::ReauthenticationRequired)
    );
    // A wrong password refreshes nothing.
    assert_eq!(
        a.reauthenticate(&password("wrong horse")).await.err(),
        Some(DeviceError::LoginFailed)
    );
    assert_eq!(
        a.sign_out_all().await.err(),
        Some(DeviceError::ReauthenticationRequired)
    );
    // The right one gives a recent session for the same device, with no approval.
    let info = a
        .reauthenticate(&password(PASSWORD))
        .await
        .expect("re-login");
    assert_eq!(info.device_id, device_before);
    assert_eq!(info.device_state, DeviceState::Trusted);
    assert_eq!(engine.device_count(NORMAL), 1);
    a.sign_out_all().await.expect("signs everything out");
    assert_eq!(a.sign_out_all().await.err(), Some(DeviceError::NotSignedIn));
    // The keys stayed, so the next sign-in is the same device.
    let info = match a
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("sign in")
    {
        SignInOutcome::SignedIn(info) => info,
        other => panic!("{other:?}"),
    };
    assert_eq!(info.device_id, device_before);
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_out_keeps_the_device_unless_asked_to_forget_it() {
    let engine = FakeEngine::new();
    let a = first_device(&engine).await;
    let (_, device, _) = a.identity().expect("store").expect("saved");
    a.sign_out(false).await.expect("sign out");
    assert!(a.identity().expect("store").is_some(), "the device stays");
    let SignInOutcome::SignedIn(info) = a.sign_in(NORMAL, &password(PASSWORD)).await.expect("in")
    else {
        panic!("same device");
    };
    assert_eq!(info.device_id, device);
    a.sign_out(true).await.expect("forget");
    assert_eq!(a.identity().expect("store"), None);
    let outcome = a.sign_in(NORMAL, &password(PASSWORD)).await.expect("in");
    assert!(
        matches!(outcome, SignInOutcome::NeedsApproval(_)),
        "{outcome:?}"
    );
    assert_eq!(engine.device_count(NORMAL), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_account_a_limit_and_a_busy_store_have_their_own_errors() {
    let engine = FakeEngine::new();
    let a = first_device(&engine).await;
    // Another sign-up or sign-in while the store holds a device is refused.
    assert_eq!(
        a.begin_sign_up(request(None)).await.err(),
        Some(DeviceError::StoreNotEmpty)
    );
    assert_eq!(
        a.sign_in("someone@else.example", &password(PASSWORD))
            .await
            .err(),
        Some(DeviceError::StoreNotEmpty)
    );
    engine.delete_account(NORMAL);
    assert_eq!(a.sign_out_all().await.err(), Some(DeviceError::AccountGone));

    let limited = FakeEngine::new();
    limited.limit_register(30);
    let c = client(&limited, "Laptop");
    assert_eq!(
        c.begin_sign_up(request(None)).await.err(),
        Some(DeviceError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_ended_elsewhere_is_not_an_account_that_is_gone() {
    // The app destroys key material on `AccountGone`, so only a deleted account may give it.
    for mode in [
        StatusMode::Normal,
        StatusMode::ServerError,
        StatusMode::Unreachable,
    ] {
        let engine = FakeEngine::new();
        let a = first_device(&engine).await;
        engine.revoke_sessions(NORMAL);
        engine.status_mode(mode);
        assert_eq!(
            a.sign_out_all().await.err(),
            Some(DeviceError::SessionExpired),
            "an alive account, status {}",
            match mode {
                StatusMode::Normal => "answers with no deletion",
                StatusMode::ServerError => "answers 500",
                StatusMode::Unreachable => "is unreachable",
            }
        );
        // Nothing was wiped: the keys and ids are still there.
        assert!(a.identity().expect("store").is_some());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_output_never_shows_a_body() {
    let secret = "SESSION-TOKEN-AND-CODE-1234";
    let response = Response {
        status: 200,
        retry_after: None,
        body: zeroize::Zeroizing::new(format!("{{\"token\":\"{secret}\"}}").into_bytes()),
    };
    let request = Request {
        method: Method::Post,
        path: "/v1/sessions/login/second-factor".to_owned(),
        bearer: Some(Zeroizing::new("BEARER-SECRET".to_owned())),
        body: Some(zeroize::Zeroizing::new(
            format!("{{\"code\":\"{secret}\"}}").into_bytes(),
        )),
    };
    for text in [
        format!("{response:?}"),
        format!("{response:#?}"),
        format!("{request:?}"),
        format!("{request:#?}"),
    ] {
        assert!(
            !text.contains(secret) && !text.contains("BEARER-SECRET"),
            "{text}"
        );
        // Nor as the bytes of the body: `83, 69, 83` is "SES".
        assert!(!text.contains("83, 69, 83"), "{text}");
    }
    assert!(format!("{request:?}").contains("/v1/sessions/login/second-factor"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_re_created_account_never_inherits_the_old_vault_key() {
    let engine = FakeEngine::new();
    let a = first_device(&engine).await;
    let before = a.store().load().expect("store").expect("saved");
    // The account is deleted and the address signs up again, from another machine.
    engine.delete_account(NORMAL);
    let _b = first_device(&engine).await;
    let outcome = a
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("sign in");
    let SignInOutcome::NeedsApproval(info) = outcome else {
        panic!("this device is new to the new account: {outcome:?}");
    };
    let after = a.store().load().expect("store").expect("saved");
    assert_ne!(info.account_id, before.account_id);
    assert_ne!(
        *after.vault_key, *before.vault_key,
        "a new account gets a new vault key"
    );
    // The same account keeps its key across sign-ins.
    let c = first_device(&FakeEngine::new()).await;
    let first = c.store().load().expect("store").expect("saved");
    c.sign_in(NORMAL, &password(PASSWORD)).await.expect("again");
    assert_eq!(
        *first.vault_key,
        *c.store().load().expect("store").expect("saved").vault_key
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_up_finishing_does_not_overwrite_a_device_signed_in_meanwhile() {
    let engine = FakeEngine::new();
    let a = client(&engine, "Laptop");
    let mut pending = a.begin_sign_up(request(None)).await.expect("begin");
    let code = engine.code_for(NORMAL);
    // Something else filled the store while the code was on its way.
    let other = StoredIdentity {
        device_keys: zeroize::Zeroizing::new([7u8; 64]),
        account_id: "other-account".to_owned(),
        device_id: "other-device".to_owned(),
        email: "other@example.com".to_owned(),
        session: None,
        vault_key: zeroize::Zeroizing::new([9u8; 32]),
    };
    a.store().save(&other).expect("save");
    assert_eq!(
        a.verify_sign_up(&mut pending, &code).await.err(),
        Some(DeviceError::StoreNotEmpty)
    );
    assert_eq!(
        a.store().load().expect("store").expect("kept").account_id,
        "other-account"
    );
    // The code was not spent: with the store empty again, the same sign-up finishes.
    a.store().clear().expect("clear");
    a.verify_sign_up(&mut pending, &code).await.expect("verify");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_body_limit_holds_with_and_without_a_content_length() {
    let (address, _task) = serve_once(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    )
    .await;
    // No Content-Length: the body ends when the server closes, and it is longer than the limit.
    let api = HttpApi::new(&address).expect("api").with_body_limit(100);
    let get = || Request {
        method: Method::Get,
        path: "/x".to_owned(),
        bearer: None,
        body: None,
    };
    assert_eq!(api.send(get()).await.err(), Some(DeviceError::Transport));
    let (address, _task) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await;
    let response = HttpApi::new(&address)
        .expect("api")
        .with_body_limit(100)
        .send(get())
        .await
        .expect("within the limit");
    assert_eq!(&response.body[..], b"hello");
    let (address, _task) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\nhello")
            .await;
    assert_eq!(
        HttpApi::new(&address)
            .expect("api")
            .with_body_limit(100)
            .send(get())
            .await
            .err(),
        Some(DeviceError::Transport)
    );
}

/// One connection served by hand: the raw request is returned, `reply` is sent.
async fn serve_once(reply: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buffer = vec![0u8; 8192];
        let n = socket.read(&mut buffer).await.expect("read");
        socket.write_all(reply.as_bytes()).await.expect("write");
        socket.shutdown().await.ok();
        String::from_utf8_lossy(&buffer[..n]).to_string()
    });
    (address, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_http_transport_does_not_follow_redirects_and_reads_retry_after() {
    use orbyn_device_client::DeviceApi;
    let (address, task) = serve_once(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let api = HttpApi::new(&address).expect("loopback http is allowed");
    let response = api
        .send(Request {
            method: Method::Get,
            path: "/v1/devices".to_owned(),
            bearer: Some(Zeroizing::new("secret-token".to_owned())),
            body: None,
        })
        .await
        .expect("the redirect is an answer, not followed");
    assert_eq!(response.status, 302);
    let seen = task.await.expect("served").to_lowercase();
    assert!(
        seen.contains("authorization: bearer secret-token"),
        "{seen}"
    );

    let (address, _task) = serve_once(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response = HttpApi::new(&address)
        .expect("api")
        .send(Request {
            method: Method::Post,
            path: "/x".to_owned(),
            bearer: None,
            body: Some(Zeroizing::new(b"{}".to_vec())),
        })
        .await
        .expect("answer");
    assert_eq!((response.status, response.retry_after), (429, Some(7)));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_app_label_is_signed_at_sign_up_and_sign_in_and_a_client_with_none_signs_the_old_messages()
 {
    let engine = FakeEngine::new();
    // The fake checks the v2 message when a label is sent and the v1 message when not, and
    // panics on a bad signature, so each of these passes only if the client signed the right one.
    let a = client(&engine, "  Laptop  ");
    let mut pending = a.begin_sign_up(request(None)).await.expect("begin");
    let code = engine.code_for(NORMAL);
    a.verify_sign_up(&mut pending, &code).await.expect("verify");
    let plain = DeviceClient::new(
        engine.clone(),
        MemoryStore::new(),
        SharedClock(engine.now.clone()),
        ClientConfig {
            device_name: " Tablet ".to_owned(),
            platform: DevicePlatform::Linux,
            app: None,
        },
    );
    plain
        .sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("an unlabelled device signs in with the v1 message");
    let b = client(&engine, "Phone");
    b.sign_in(NORMAL, &password(PASSWORD))
        .await
        .expect("a labelled device signs in with the v2 message");
    assert_eq!(
        engine.device_apps(NORMAL),
        vec![
            Some(DeviceApp::Engineering),
            None,
            Some(DeviceApp::Engineering)
        ]
    );
}

/// A store whose next `failures` saves fail, then behaves as a memory store.
struct FlakyStore {
    inner: MemoryStore,
    failures: std::sync::Mutex<usize>,
}

impl FlakyStore {
    fn failing(failures: usize) -> Self {
        Self {
            inner: MemoryStore::new(),
            failures: std::sync::Mutex::new(failures),
        }
    }
}

impl KeyStore for FlakyStore {
    fn load(&self) -> Result<Option<StoredIdentity>, StoreError> {
        self.inner.load()
    }

    fn save(&self, identity: &StoredIdentity) -> Result<(), StoreError> {
        let mut left = self.failures.lock().expect("lock");
        if *left > 0 {
            *left -= 1;
            return Err(StoreError);
        }
        drop(left);
        self.inner.save(identity)
    }

    fn clear(&self) -> Result<(), StoreError> {
        self.inner.clear()
    }
}

fn flaky_client(
    engine: &FakeEngine,
    failures: usize,
) -> DeviceClient<FakeEngine, FlakyStore, SharedClock> {
    DeviceClient::new(
        engine.clone(),
        FlakyStore::failing(failures),
        SharedClock(engine.now.clone()),
        ClientConfig {
            device_name: "Laptop".to_owned(),
            platform: DevicePlatform::Linux,
            app: None,
        },
    )
}

#[test]
fn debug_of_a_password_never_shows_the_text() {
    let secret = "correct horse battery staple";
    let password = Password::new(secret);
    for text in [
        format!("{password:?}"),
        format!("{password:#?}"),
        format!("{:?}", Some(&password)),
        format!("{:?}", vec![password.clone()]),
    ] {
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("horse"), "{text}");
        assert!(text.contains("Password(..)"), "{text}");
    }
    // It still works as a password.
    assert_eq!(password.as_str(), secret);
    assert_eq!(password.as_bytes(), secret.as_bytes());
    assert!(!password.is_empty() && Password::from(String::new()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_save_after_the_code_is_spent_keeps_the_keys_and_retry_save_finishes() {
    let engine = FakeEngine::new();
    let a = flaky_client(&engine, 2);
    let mut pending = a.begin_sign_up(request(None)).await.expect("begin");
    let code = engine.code_for(NORMAL);
    // The code is accepted, the save fails: the account exists and the code is spent.
    assert!(matches!(
        a.verify_sign_up(&mut pending, &code).await,
        Err(DeviceError::Store(_))
    ));
    assert_eq!(engine.device_count(NORMAL), 1);
    assert_eq!(a.identity().expect("store"), None, "nothing was saved");
    let verifies = |engine: &FakeEngine| {
        engine
            .log()
            .iter()
            .filter(|(path, _)| path.ends_with("email/verify"))
            .count()
    };
    assert_eq!(verifies(&engine), 1);

    // The same call again, whatever the code, retries the save without asking the server.
    assert!(matches!(
        a.verify_sign_up(&mut pending, "00000000").await,
        Err(DeviceError::Store(_))
    ));
    assert_eq!(verifies(&engine), 1, "the spent code was not sent again");

    // The store recovered: the keys and the session saved are the ones the server answered with.
    let session = a.retry_save(&mut pending).expect("retry");
    assert_eq!(session.device_state, DeviceState::Trusted);
    assert_eq!(verifies(&engine), 1);
    let (account, device, email) = a.identity().expect("store").expect("saved");
    assert_eq!(
        (account, device, email),
        (
            session.account_id.clone(),
            session.device_id.clone(),
            NORMAL.to_owned()
        )
    );
    // The saved device key is the one the server knows: it signs a trusted start.
    a.reauthenticate(&password(PASSWORD))
        .await
        .expect("a trusted start with the saved key");

    // Nothing is left to save, and a finished sign-up is not verified again.
    assert_eq!(
        a.retry_save(&mut pending).err(),
        Some(DeviceError::InvalidInput("there is nothing to save"))
    );
    assert_eq!(
        a.verify_sign_up(&mut pending, &code).await.err(),
        Some(DeviceError::InvalidInput("this sign-up is finished"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_save_with_no_spent_code_or_a_store_that_holds_a_device_saves_nothing() {
    let engine = FakeEngine::new();
    let a = flaky_client(&engine, 0);
    let mut pending = a.begin_sign_up(request(None)).await.expect("begin");
    assert_eq!(
        a.retry_save(&mut pending).err(),
        Some(DeviceError::InvalidInput("there is nothing to save"))
    );

    // The save fails, and a device lands in the store before the retry: it is never overwritten.
    let b = flaky_client(&engine, 1);
    let mut second = b
        .begin_sign_up(SignUpRequest {
            email: "other@example.com".to_owned(),
            password: password(PASSWORD),
            invite: None,
        })
        .await
        .expect("begin");
    let code = engine.code_for("other@example.com");
    assert!(b.verify_sign_up(&mut second, &code).await.is_err());
    let stored = StoredIdentity {
        device_keys: orbyn_crypto::DeviceKeys::generate()
            .expect("keys")
            .to_bytes(),
        account_id: "x".into(),
        device_id: "y".into(),
        email: "z@example.com".into(),
        session: None,
        vault_key: Zeroizing::new([9u8; 32]),
    };
    b.store().save(&stored).expect("save");
    assert_eq!(
        b.retry_save(&mut second).err(),
        Some(DeviceError::StoreNotEmpty)
    );
    assert_eq!(
        b.store().load().expect("load").expect("kept").account_id,
        "x"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn check_invite_says_yes_to_a_good_code_and_one_answer_to_every_bad_one() {
    let engine = FakeEngine::new();
    let a = client(&engine, "Laptop");
    // A server that asks for no invites accepts any code.
    assert_eq!(a.check_invite("anything").await, Ok(()));

    engine.add_invite("ABCD1234");
    // Case, spaces and hyphens are the server's business; the code goes as typed.
    assert_eq!(a.check_invite("abcd-1234").await, Ok(()));
    for bad in ["WRONG-CODE", "", "ABCD12345"] {
        assert_eq!(
            a.check_invite(bad).await.err(),
            Some(DeviceError::InviteInvalid),
            "{bad:?}"
        );
    }
    // Checking spends nothing and signs nothing up.
    assert_eq!(a.check_invite("abcd-1234").await, Ok(()));
    assert_eq!(a.identity().expect("store"), None);
    let sent: Vec<_> = engine
        .log()
        .into_iter()
        .filter(|(path, _)| path.contains("invites/check"))
        .collect();
    assert_eq!(sent.len(), 6);
    assert!(sent.iter().any(|(_, body)| body.contains("abcd-1234")));
}

#[tokio::test(flavor = "multi_thread")]
async fn check_invite_maps_a_limit_and_a_dead_network() {
    struct Status(u16, Option<u64>);
    impl DeviceApi for Status {
        async fn send(&self, _: Request) -> Result<Response, DeviceError> {
            match self.0 {
                0 => Err(DeviceError::Transport),
                status => Ok(Response {
                    status,
                    retry_after: self.1,
                    body: Zeroizing::new(br#"{"code":"too_many_attempts","message":"x"}"#.to_vec()),
                }),
            }
        }
    }
    let config = || ClientConfig {
        device_name: "Laptop".to_owned(),
        platform: DevicePlatform::Linux,
        app: None,
    };
    let limited = DeviceClient::new(
        Status(429, Some(30)),
        MemoryStore::new(),
        SharedClock(Arc::new(AtomicI64::new(0))),
        config(),
    );
    assert_eq!(
        limited.check_invite("X").await.err(),
        Some(DeviceError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        })
    );
    let offline = DeviceClient::new(
        Status(0, None),
        MemoryStore::new(),
        SharedClock(Arc::new(AtomicI64::new(0))),
        config(),
    );
    assert_eq!(
        offline.check_invite("X").await.err(),
        Some(DeviceError::Transport)
    );
}
