//! The device client against the real server on Postgres, over a real loopback socket: sign-up,
//! two devices, zone keys, push and pull, a conflict, the snapshot, the notices stream and the
//! status. Ignored unless run with `--include-ignored` and `DATABASE_URL`.

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use orbyn_auth_client as auth;
use orbyn_client::Engine;
use orbyn_contracts as wire;
use orbyn_core::accounts::AuthSecrets;
use orbyn_core::{Accounts, Database};
use orbyn_device_client::{
    ClientConfig, DeviceClient, DeviceError, HttpApi, KeyStore, MemoryStore, Notice, NoticeConfig,
    SignInOutcome, SignUpRequest, SyncState, SystemClock,
};
use orbyn_server::{AppState, Readiness, router};
use orbyn_store::{Hub, Store};
use orbyn_sync::Fields;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

const ZONE: &str = "engineering.settings";
const PASSWORD: &str = "correct horse battery staple";

struct Up;
impl Readiness for Up {
    fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

static SETUP: OnceLock<String> = OnceLock::new();
static MAILBOX: OnceLock<orbyn_core::mail::Capture> = OnceLock::new();

/// The verification code sent to `email`: delivers the queue into the shared mailbox until it shows.
async fn code_sent_to(pool: &orbyn_core::sqlx::PgPool, email: &str) -> String {
    let mailbox = MAILBOX.get_or_init(orbyn_core::mail::Capture::default);
    let secrets = AuthSecrets::from_encoded(SETUP.get().expect("setup")).expect("setup");
    let to = auth::normalize_email(email).expect("email");
    for _ in 0..200 {
        orbyn_core::mail::deliver_queued(pool, &secrets, mailbox)
            .await
            .expect("deliver");
        if let Some(code) = mailbox.code_for(&to) {
            return code;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no verification code was sent to {to}");
}

struct Server {
    app: axum::Router,
    db: Database,
    base: String,
}

impl Server {
    /// The real app on Postgres, served on a loopback port.
    async fn start() -> Self {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = Database::connect(&url).await.expect("connect to Postgres");
        db.migrate().await.expect("migrate");
        let setup = SETUP.get_or_init(|| AuthSecrets::generate().to_string());
        let secrets = AuthSecrets::from_encoded(setup).expect("setup");
        let accounts =
            Accounts::new(db.pool().clone(), secrets).with_signup(orbyn_core::SignupMode::Open);
        let hub = Hub::start(db.pool().clone());
        let store = Store::new(db.pool().clone(), hub);
        let state = AppState::new(Arc::new(Up))
            .with_accounts(accounts)
            .with_store(store);
        let app = router(state, &[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let service = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, service).await });
        Self {
            app,
            db,
            base: format!("http://{address}"),
        }
    }

    fn device(&self, name: &str) -> DeviceClient<HttpApi, MemoryStore, SystemClock> {
        DeviceClient::new(
            HttpApi::new(&self.base).expect("loopback"),
            MemoryStore::new(),
            SystemClock,
            ClientConfig {
                device_name: name.to_owned(),
                platform: wire::DevicePlatform::Linux,
                app: Some(wire::DeviceApp::Engineering),
            },
        )
    }

    /// A call straight into the app (no socket), for the approval steps.
    async fn call(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let mut request = request.body(body).expect("request");
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            40_000,
        )));
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 << 20)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    async fn ok<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
        expected: StatusCode,
    ) -> T {
        let (status, value) = self.call(method, path, token, body).await;
        assert_eq!(status, expected, "{path}: {value}");
        serde_json::from_value(value).expect("wire type")
    }
}

type Client = DeviceClient<HttpApi, MemoryStore, SystemClock>;

fn password() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.to_owned())
}

fn email() -> String {
    format!("device-{}@example.test", Uuid::new_v4().simple())
}

async fn sign_up(server: &Server, client: &Client, email: &str) {
    let mut pending = client
        .begin_sign_up(SignUpRequest {
            email: email.to_owned(),
            password: password(),
            invite: None,
        })
        .await
        .expect("begin");
    let code = code_sent_to(server.db.pool(), email).await;
    client
        .verify_sign_up(&mut pending, &code)
        .await
        .expect("verify");
}

fn token_of(client: &Client) -> String {
    let identity = client.store().load().expect("store").expect("signed in");
    identity.session.expect("a session").token.to_string()
}

fn device_id_of(client: &Client) -> String {
    client
        .store()
        .load()
        .expect("store")
        .expect("signed in")
        .device_id
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("json")
}

/// The whole two-way approval over HTTP, with the person confirming that both screens show the
/// same digits (the real client API for this is the next change).
async fn approve(
    server: &Server,
    (approver_token, approver): (&str, &mut Engine),
    (new_token, new, new_id): (&str, &mut Engine, &str),
) {
    let list: wire::DeviceList = server
        .ok(
            Method::GET,
            "/v1/devices",
            approver_token,
            None,
            StatusCode::OK,
        )
        .await;
    let pending = list
        .devices
        .iter()
        .find(|d| d.id == new_id)
        .expect("the new device is listed")
        .clone();
    let (mut pa, create) = approver
        .start_approval(&pending, now_secs())
        .expect("start");
    let created: wire::ApprovalCreated = server
        .ok(
            Method::POST,
            "/v1/devices/approvals",
            approver_token,
            Some(value(&create)),
            StatusCode::CREATED,
        )
        .await;
    let step = |name: &str| format!("/v1/devices/approvals/{}/{name}", created.id);
    let view = current_approval(server, new_token).await;
    // These devices named their app, so each joins with the description it signed in with
    // (the honest server lists the same name).
    let (pd, nonce) = new
        .join_approval_labelled(
            &view,
            now_secs(),
            &pending.name,
            wire::DevicePlatform::Linux,
            wire::DeviceApp::Engineering,
        )
        .expect("join");
    let (status, body) = server
        .call(Method::POST, &step("nonce"), new_token, Some(value(&nonce)))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let on_approver: wire::PendingApproval = server
        .ok(
            Method::GET,
            &format!("/v1/devices/approvals/{}", created.id),
            approver_token,
            None,
            StatusCode::OK,
        )
        .await;
    let reveal = pa.reveal(&on_approver).expect("reveal");
    let (status, body) = server
        .call(
            Method::POST,
            &step("reveal"),
            approver_token,
            Some(value(&reveal)),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let view = current_approval(server, new_token).await;
    let on_new = pd.sas(&view).expect("sas");
    assert_eq!(pa.sas(), Some(on_new), "both screens show the same digits");
    let confirm = approver.confirm_approval(pa, &list).expect("confirm");
    let (status, body) = server
        .call(
            Method::POST,
            &step("confirm"),
            approver_token,
            Some(value(&confirm)),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let view = current_approval(server, new_token).await;
    let code = new
        .finish_approval(pd, &view, None, now_secs())
        .expect("finish");
    let (status, body) = server
        .call(
            Method::POST,
            &step("code"),
            new_token,
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn current_approval(server: &Server, token: &str) -> wire::PendingApproval {
    let current: wire::CurrentDevice = server
        .ok(
            Method::GET,
            "/v1/devices/current",
            token,
            None,
            StatusCode::OK,
        )
        .await;
    current.approval.expect("an open approval")
}

/// One field set on a record, stamped by the engine's clock.
fn set(engine: &mut Engine, zone: &str, id: &str, name: &str, to: Value) {
    let stamp = engine.tick(u64::try_from(now_secs()).unwrap_or(0) * 1000);
    let mut fields = Fields::default();
    fields.set(name, to, stamp);
    engine
        .stage(zone, "person_settings", id, &fields)
        .expect("stage");
}

fn field(engine: &Engine, zone: &str, id: &str, name: &str) -> Option<Value> {
    engine.record(zone, id)?.get(name).cloned()
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn two_devices_sync_records_keys_and_a_conflict_through_the_real_server() {
    let server = Server::start().await;
    let email = email();
    let a = server.device("Laptop");
    sign_up(&server, &a, &email).await;
    let b = server.device("Desktop");
    let outcome = b.sign_in(&email, &password()).await.expect("sign in");
    assert!(
        matches!(outcome, SignInOutcome::NeedsApproval(_)),
        "{outcome:?}"
    );

    // A pending device cannot sync.
    let mut engine_b = b.open_engine(None).expect("engine");
    assert_eq!(
        b.sync_all(&mut engine_b).await.err(),
        Some(DeviceError::DeviceNotTrusted)
    );
    assert_eq!(b.status().borrow().state, SyncState::Failed);

    // A stages a record and syncs: the zone, its key and the sealed record reach the server.
    let mut engine_a = a.open_engine(None).expect("engine");
    set(
        &mut engine_a,
        ZONE,
        "person",
        "default_theme",
        json!("dark"),
    );
    let report = a.sync_all(&mut engine_a).await.expect("pass");
    assert_eq!(report.zones.len(), 1);
    assert_eq!(
        (report.zones[0].zone.as_str(), report.zones[0].pushed),
        (ZONE, 1)
    );
    assert!(!engine_a.has_pending(ZONE));
    {
        let status = a.status();
        let status = status.borrow();
        assert_eq!(status.state, SyncState::Idle);
        assert!(status.last_synced.is_some());
    }
    // The server holds ciphertext, never the value.
    let (length, at): (i32, i32) = orbyn_core::sqlx::query_as(
        "SELECT length(r.ciphertext), position('dark'::bytea in r.ciphertext)
         FROM records r JOIN zones z ON z.id = r.zone_id
         WHERE z.name = $1 AND r.record_id = 'person'",
    )
    .bind(ZONE)
    .fetch_one(server.db.pool())
    .await
    .expect("the record is on the server");
    assert!(
        length > 0 && at == 0,
        "ciphertext of {length} bytes, plaintext found at {at}"
    );

    // A approves B and hands it the zone key; B's pass takes the key and pulls the record.
    approve(
        &server,
        (&token_of(&a), &mut engine_a),
        (&token_of(&b), &mut engine_b, &device_id_of(&b)),
    )
    .await;
    // Trusted but without the key yet, B stages work: its pass reports it is waiting for the key
    // and fails nothing; the work stays staged.
    set(
        &mut engine_b,
        ZONE,
        "extra",
        "quit_confirmation",
        json!("hold"),
    );
    let waiting = b
        .sync_all(&mut engine_b)
        .await
        .expect("a pass without the key");
    assert!(
        waiting
            .zones
            .iter()
            .any(|z| z.zone == ZONE && z.waiting_for_key),
        "{waiting:?}"
    );
    assert!(engine_b.has_pending(ZONE));
    let devices = a.devices().await.expect("devices");
    a.send_keys(&mut engine_a, ZONE, &devices)
        .await
        .expect("keys");
    let report = b.sync_all(&mut engine_b).await.expect("pass");
    assert_eq!(report.keys_accepted, vec![ZONE.to_owned()]);
    assert!(
        !engine_b.has_pending(ZONE),
        "the staged work went up once the key arrived"
    );
    assert_eq!(
        field(&engine_b, ZONE, "person", "default_theme"),
        Some(json!("dark"))
    );

    // Both edit the same record while apart, different fields; the passes merge them.
    set(
        &mut engine_a,
        ZONE,
        "person",
        "branch_name_prefix",
        json!("feat"),
    );
    set(&mut engine_b, ZONE, "person", "preview_zoom", json!(2));
    set(
        &mut engine_b,
        ZONE,
        "person",
        "default_theme",
        json!("light"),
    );
    b.sync_all(&mut engine_b).await.expect("b first");
    a.sync_all(&mut engine_a)
        .await
        .expect("a second: a conflict, merged");
    b.sync_all(&mut engine_b).await.expect("b again");
    for engine in [&engine_a, &engine_b] {
        assert_eq!(
            field(engine, ZONE, "person", "branch_name_prefix"),
            Some(json!("feat"))
        );
        assert_eq!(
            field(engine, ZONE, "person", "preview_zoom"),
            Some(json!(2))
        );
        assert_eq!(
            field(engine, ZONE, "person", "default_theme"),
            Some(json!("light"))
        );
    }

    // The snapshot is all a host keeps: a device restored from it sees the same record.
    let saved = serde_json::to_vec(&engine_b.snapshot()).expect("snapshot");
    let restored = b
        .open_engine(Some(serde_json::from_slice(&saved).expect("snapshot")))
        .expect("restore");
    assert_eq!(
        field(&restored, ZONE, "person", "preview_zoom"),
        Some(json!(2))
    );
    // A snapshot of another device is refused.
    assert!(matches!(
        a.open_engine(Some(serde_json::from_slice(&saved).expect("snapshot"))),
        Err(DeviceError::InvalidInput(_))
    ));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn purged_history_makes_a_zone_start_again_instead_of_failing() {
    let server = Server::start().await;
    let email = email();
    let a = server.device("Laptop");
    sign_up(&server, &a, &email).await;
    let mut engine = a.open_engine(None).expect("engine");
    set(&mut engine, ZONE, "person", "default_theme", json!("dark"));
    a.sync_all(&mut engine).await.expect("pass");
    // The server purges history this device has not seen, so its change token is too old.
    orbyn_core::sqlx::query("UPDATE zones SET purge_floor = 1000000 WHERE name = $1")
        .bind(ZONE)
        .execute(server.db.pool())
        .await
        .expect("purge");
    set(&mut engine, ZONE, "person", "preview_zoom", json!(2));
    a.sync_all(&mut engine)
        .await
        .expect("a 410 starts the zone again");
    assert!(!engine.has_pending(ZONE));
    assert_eq!(
        field(&engine, ZONE, "person", "default_theme"),
        Some(json!("dark"))
    );
    assert_eq!(
        field(&engine, ZONE, "person", "preview_zoom"),
        Some(json!(2))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_failed_network_keeps_the_work_and_says_offline() {
    let server = Server::start().await;
    let email = email();
    let a = server.device("Laptop");
    sign_up(&server, &a, &email).await;
    let mut engine = a.open_engine(None).expect("engine");
    set(&mut engine, ZONE, "person", "default_theme", json!("dark"));
    // The same identity, aimed at an address where nothing listens.
    let lost: Client = DeviceClient::new(
        HttpApi::new("http://127.0.0.1:1").expect("loopback"),
        MemoryStore::new(),
        SystemClock,
        ClientConfig {
            device_name: "Laptop".to_owned(),
            platform: wire::DevicePlatform::Linux,
            app: Some(wire::DeviceApp::Engineering),
        },
    );
    lost.store()
        .save(&a.store().load().expect("store").expect("saved"))
        .expect("save");
    assert_eq!(
        lost.sync_all(&mut engine).await.err(),
        Some(DeviceError::Transport)
    );
    assert_eq!(lost.status().borrow().state, SyncState::Offline);
    assert!(engine.has_pending(ZONE), "the work is still staged");
    // Back on the real address the next pass sends it.
    a.sync_all(&mut engine).await.expect("pass");
    assert!(!engine.has_pending(ZONE));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_notices_stream_tells_a_device_that_another_changed_a_zone() {
    let server = Server::start().await;
    let email = email();
    let a = server.device("Laptop");
    sign_up(&server, &a, &email).await;
    let b = server.device("Desktop");
    b.sign_in(&email, &password()).await.expect("sign in");
    let mut engine_a = a.open_engine(None).expect("engine");
    let mut engine_b = b.open_engine(None).expect("engine");
    set(
        &mut engine_a,
        ZONE,
        "person",
        "default_theme",
        json!("dark"),
    );
    a.sync_all(&mut engine_a).await.expect("pass");
    approve(
        &server,
        (&token_of(&a), &mut engine_a),
        (&token_of(&b), &mut engine_b, &device_id_of(&b)),
    )
    .await;
    let devices = a.devices().await.expect("devices");
    a.send_keys(&mut engine_a, ZONE, &devices)
        .await
        .expect("keys");
    b.sync_all(&mut engine_b).await.expect("pass");

    let mut notices = a.notices(NoticeConfig::default()).expect("stream");
    assert_eq!(next(&mut notices).await, Notice::Connected);
    set(&mut engine_b, ZONE, "person", "preview_zoom", json!(3));
    b.sync_all(&mut engine_b).await.expect("pass");
    let mut heard = None;
    for _ in 0..10 {
        if let Notice::ZoneChanged { zone, .. } = next(&mut notices).await {
            heard = Some(zone);
            break;
        }
    }
    assert_eq!(heard.as_deref(), Some(ZONE));
    drop(notices);

    // A session the server no longer knows is rejected, and the stream stops.
    orbyn_core::sqlx::query("UPDATE sessions SET revoked_at = now() WHERE device_id = $1::uuid")
        .bind(device_id_of(&b))
        .execute(server.db.pool())
        .await
        .expect("revoke");
    let mut notices = b.notices(NoticeConfig::default()).expect("stream");
    assert_eq!(
        next(&mut notices).await,
        Notice::Rejected {
            code: "unauthorized".to_owned()
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), notices.next())
            .await
            .expect("ends"),
        None
    );
}

async fn next(notices: &mut orbyn_device_client::Notices) -> Notice {
    tokio::time::timeout(Duration::from_secs(10), notices.next())
        .await
        .expect("a notice in time")
        .expect("the stream is open")
}

/// Two trusted devices of one account, each with an engine, and the zone's key shared.
async fn two_trusted_devices(server: &Server) -> (Client, Engine, Client, Engine) {
    let email = email();
    let a = server.device("Laptop");
    sign_up(server, &a, &email).await;
    let b = server.device("Desktop");
    b.sign_in(&email, &password()).await.expect("sign in");
    let mut engine_a = a.open_engine(None).expect("engine");
    let mut engine_b = b.open_engine(None).expect("engine");
    set(
        &mut engine_a,
        ZONE,
        "person",
        "default_theme",
        json!("dark"),
    );
    a.sync_all(&mut engine_a).await.expect("pass");
    approve(
        server,
        (&token_of(&a), &mut engine_a),
        (&token_of(&b), &mut engine_b, &device_id_of(&b)),
    )
    .await;
    let devices = a.devices().await.expect("devices");
    a.send_keys(&mut engine_a, ZONE, &devices)
        .await
        .expect("keys");
    b.sync_all(&mut engine_b).await.expect("pass");
    (a, engine_a, b, engine_b)
}

/// The real transport, except that just before it forwards the first upload it sends another
/// device's upload, so the server's records have changed under the first one: a real conflict.
struct RacingApi {
    inner: HttpApi,
    first: std::sync::Mutex<Option<orbyn_device_client::Request>>,
    answer: std::sync::Mutex<Option<orbyn_device_client::Response>>,
}

impl orbyn_device_client::DeviceApi for RacingApi {
    fn base_url(&self) -> Option<&str> {
        self.inner.base_url()
    }

    async fn send(
        &self,
        request: orbyn_device_client::Request,
    ) -> Result<orbyn_device_client::Response, DeviceError> {
        let rival = if request.path.ends_with("/changes")
            && request.method == orbyn_device_client::Method::Post
        {
            self.first.lock().expect("lock").take()
        } else {
            None
        };
        if let Some(rival) = rival {
            let answer = self.inner.send(rival).await?;
            *self.answer.lock().expect("lock") = Some(answer);
        }
        self.inner.send(request).await
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_conflict_during_an_upload_is_merged_and_the_upload_goes_again() {
    let server = Server::start().await;
    let (a, mut engine_a, b, mut engine_b) = two_trusted_devices(&server).await;
    // B's change is built and held back; A's client sends it just before its own upload.
    set(&mut engine_b, ZONE, "person", "preview_zoom", json!(2));
    let rival = engine_b
        .build_upload(ZONE)
        .expect("build")
        .expect("something to send");
    let racing: DeviceClient<RacingApi, MemoryStore, SystemClock> = DeviceClient::new(
        RacingApi {
            inner: HttpApi::new(&server.base).expect("loopback"),
            first: std::sync::Mutex::new(Some(orbyn_device_client::Request {
                method: orbyn_device_client::Method::Post,
                path: format!("/v1/zones/{ZONE}/changes"),
                bearer: Some(Zeroizing::new(token_of(&b))),
                body: Some(Zeroizing::new(serde_json::to_vec(&rival).expect("json"))),
            })),
            answer: std::sync::Mutex::new(None),
        },
        MemoryStore::new(),
        SystemClock,
        ClientConfig {
            device_name: "Laptop".to_owned(),
            platform: wire::DevicePlatform::Linux,
            app: Some(wire::DeviceApp::Engineering),
        },
    );
    racing
        .store()
        .save(&a.store().load().expect("store").expect("saved"))
        .expect("save");
    set(
        &mut engine_a,
        ZONE,
        "person",
        "branch_name_prefix",
        json!("feat"),
    );
    let report = racing
        .sync_all(&mut engine_a)
        .await
        .expect("the conflict merges");
    assert_eq!(
        report.zones[0].pushed, 1,
        "A's change went up on the second try"
    );
    // B's held-back upload did land, and B finishes it.
    let answer = racing
        .api()
        .answer
        .lock()
        .expect("lock")
        .take()
        .expect("B's answer");
    assert_eq!(answer.status, 200);
    let result: wire::UploadResult = serde_json::from_slice(&answer.body).expect("result");
    engine_b.upload_succeeded(ZONE, &result).expect("saved");
    a.sync_all(&mut engine_a).await.expect("pass");
    b.sync_all(&mut engine_b).await.expect("pass");
    for engine in [&engine_a, &engine_b] {
        assert_eq!(
            field(engine, ZONE, "person", "preview_zoom"),
            Some(json!(2))
        );
        assert_eq!(
            field(engine, ZONE, "person", "branch_name_prefix"),
            Some(json!("feat"))
        );
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_zone_made_after_the_approval_reaches_the_other_device_with_its_key() {
    let server = Server::start().await;
    let (a, mut engine_a, b, mut engine_b) = two_trusted_devices(&server).await;
    // A makes a second zone: its key is sealed to B in the same pass, with no explicit call.
    set(
        &mut engine_a,
        "engineering.profiles",
        "p1",
        "name",
        json!("fast"),
    );
    a.sync_all(&mut engine_a).await.expect("pass");
    let report = b.sync_all(&mut engine_b).await.expect("pass");
    assert!(
        report
            .keys_accepted
            .contains(&"engineering.profiles".to_owned()),
        "{report:?}"
    );
    assert_eq!(
        field(&engine_b, "engineering.profiles", "p1", "name"),
        Some(json!("fast"))
    );
}
