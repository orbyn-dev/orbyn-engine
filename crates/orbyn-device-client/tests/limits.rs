//! The limits inside one pass: a server that always answers 409 `record_changed`, or always 410
//! `token_expired`, must not hold a pass in a loop. The pass stops, says why and keeps the work
//! staged. The transport is scripted; no engine is needed.

use base64::Engine as _;
use orbyn_contracts as wire;
use orbyn_crypto::DeviceKeys;
use orbyn_device_client::{
    ClientConfig, DeviceApi, DeviceClient, DeviceError, KeyStore, MemoryStore, Method, Request,
    Response, StoredIdentity, StoredSession, SystemClock,
};
use orbyn_sync::Fields;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

const ZONE: &str = "engineering.settings";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Upload {
    AlwaysConflicts,
    AlwaysExpired,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fetch {
    Empty,
    AlwaysExpired,
}

struct Script {
    devices: Value,
    upload: Upload,
    fetch: Fetch,
    gets: AtomicUsize,
    posts: AtomicUsize,
    seen: Mutex<Vec<String>>,
}

fn answer(status: u16, body: Value) -> Result<Response, DeviceError> {
    Ok(Response {
        status,
        retry_after: None,
        body: Zeroizing::new(serde_json::to_vec(&body).expect("json")),
    })
}

impl DeviceApi for Script {
    async fn send(&self, request: Request) -> Result<Response, DeviceError> {
        // Lets the runtime run its timers, so a pass stuck in a loop is stopped by the deadline.
        tokio::task::yield_now().await;
        self.seen
            .lock()
            .expect("lock")
            .push(format!("{:?} {}", request.method, request.path));
        let path = request.path.as_str();
        match (request.method, path) {
            (Method::Get, "/v1/devices") => answer(200, self.devices.clone()),
            (Method::Get, "/v1/keychain/envelopes") => answer(200, json!({"envelopes": []})),
            (Method::Get, "/v1/zones") => answer(
                200,
                json!({"zones": [{"zone": ZONE, "token": "t0", "deleted": false, "created_at": "2026-01-01T00:00:00Z"}], "next": null}),
            ),
            (Method::Get, p) if p.contains("/changes") => {
                self.gets.fetch_add(1, Ordering::SeqCst);
                match self.fetch {
                    Fetch::Empty => answer(
                        200,
                        json!({"records": [], "token": "t1", "more": false, "zone_deleted": false}),
                    ),
                    Fetch::AlwaysExpired => {
                        answer(410, json!({"code": "token_expired", "message": "x"}))
                    }
                }
            }
            (Method::Post, p) if p.ends_with("/changes") => {
                self.posts.fetch_add(1, Ordering::SeqCst);
                match self.upload {
                    Upload::AlwaysConflicts => answer(
                        409,
                        json!({"code": "record_changed", "message": "x", "conflicts": []}),
                    ),
                    Upload::AlwaysExpired => {
                        answer(410, json!({"code": "token_expired", "message": "x"}))
                    }
                }
            }
            _ => answer(404, json!({"code": "not_found", "message": "x"})),
        }
    }
}

type Client = DeviceClient<Script, MemoryStore, SystemClock>;

fn client(upload: Upload, fetch: Fetch) -> Client {
    let keys = DeviceKeys::generate().expect("keys");
    let public = keys.public();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let device_id = uuid::Uuid::new_v4().to_string();
    let account_id = uuid::Uuid::new_v4().to_string();
    let devices = json!({"devices": [{
        "id": device_id, "name": "Laptop", "platform": "linux", "state": "trusted",
        "signing_key": b64.encode(public.signing), "agreement_key": b64.encode(public.agreement),
        "created_at": "2026-01-01T00:00:00Z", "approved_by": null, "approval_signature": null,
        "current": true,
    }], "removals": []});
    let store = MemoryStore::new();
    store
        .save(&StoredIdentity {
            device_keys: keys.to_bytes(),
            account_id,
            device_id,
            email: "a@example.test".to_owned(),
            session: Some(StoredSession {
                token: Zeroizing::new("token".to_owned()),
                expires_at: "2027-01-01T00:00:00Z".to_owned(),
            }),
            vault_key: Zeroizing::new([5u8; 32]),
        })
        .expect("save");
    DeviceClient::new(
        Script {
            devices,
            upload,
            fetch,
            gets: AtomicUsize::new(0),
            posts: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        },
        store,
        SystemClock,
        ClientConfig {
            device_name: "Laptop".to_owned(),
            platform: wire::DevicePlatform::Linux,
            app: None,
        },
    )
}

/// An engine with a key for the zone and one record waiting to go up.
fn staged(client: &Client) -> orbyn_client::Engine {
    let mut engine = client.open_engine(None).expect("engine");
    engine.create_zone_key(ZONE).expect("key");
    let stamp = engine.tick(1_800_000_000_000);
    let mut fields = Fields::default();
    fields.set("default_theme", json!("dark"), stamp);
    engine
        .stage(ZONE, "person_settings", "person", &fields)
        .expect("stage");
    engine
}

/// A pass that is stuck in a loop would hang the test, so every pass has a deadline.
async fn pass(client: &Client, engine: &mut orbyn_client::Engine) -> Result<(), DeviceError> {
    tokio::time::timeout(Duration::from_secs(10), client.sync_all(engine))
        .await
        .expect("the pass ended (it is not stuck in a loop)")
        .map(|_| ())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_always_answers_a_conflict_stops_the_pass_after_eight_rounds() {
    let client = client(Upload::AlwaysConflicts, Fetch::Empty);
    let mut engine = staged(&client);
    let error = pass(&client, &mut engine).await.err();
    assert_eq!(
        error,
        Some(DeviceError::Server {
            status: 409,
            code: "record_changed".to_owned()
        })
    );
    assert_eq!(
        client.api().posts.load(Ordering::SeqCst),
        8,
        "eight uploads, no more"
    );
    assert!(engine.has_pending(ZONE), "the work is still staged");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_always_says_the_token_expired_on_a_pull_stops_after_three_restarts() {
    let client = client(Upload::AlwaysConflicts, Fetch::AlwaysExpired);
    let mut engine = staged(&client);
    let error = pass(&client, &mut engine).await.err();
    assert!(
        matches!(error, Some(DeviceError::Server { status: 410, .. })),
        "{error:?}"
    );
    // The first fetch and three restarts.
    assert_eq!(client.api().gets.load(Ordering::SeqCst), 4);
    assert_eq!(
        client.api().posts.load(Ordering::SeqCst),
        0,
        "nothing was uploaded"
    );
    assert!(engine.has_pending(ZONE));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_always_says_the_token_expired_on_an_upload_stops_after_three_rounds() {
    let client = client(Upload::AlwaysExpired, Fetch::Empty);
    let mut engine = staged(&client);
    let error = pass(&client, &mut engine).await.err();
    assert!(
        matches!(error, Some(DeviceError::Server { status: 410, .. })),
        "{error:?}"
    );
    assert_eq!(client.api().posts.load(Ordering::SeqCst), 3);
    assert_eq!(client.api().gets.load(Ordering::SeqCst), 3);
    assert!(engine.has_pending(ZONE));
}
