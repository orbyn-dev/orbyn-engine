//! The approver's calls over a scripted transport: a network failure during the reveal, the time
//! left, the redacted `Debug`, and an approval that already ended. The real server's side of the
//! same steps is in `orbyn-server/tests/device_client.rs`.

use base64::Engine as _;
use orbyn_device_client::{
    ApproverApproval, ApproverState, ClientConfig, Clock, DeviceApi, DeviceClient, DeviceError,
    DeviceKeys, DevicePlatform, Engine, KeyStore, MemoryStore, Method, Request, Response,
    StoredIdentity, StoredSession, Zeroizing,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ACCOUNT: &str = "0a0a0a0a-0000-4000-8000-000000000001";
const APPROVER: &str = "0000000a-0000-4000-8000-00000000000a";
const NEW: &str = "0000000c-0000-4000-8000-00000000000c";
/// 2027-01-15T08:00:00Z.
const NOW: i64 = 1_800_000_000;
/// Ten minutes after `NOW`.
const EXPIRES: &str = "2027-01-15T08:10:00.000Z";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reveal {
    Works,
    /// The network fails this many times before the request goes through.
    NetworkFails(usize),
    /// The request reaches the server and is kept, but the answer is lost, once.
    AnswerLostOnce,
}

struct State {
    create: Option<Value>,
    reveal: Reveal,
    approver_nonce: Option<String>,
    /// The server says the approval ended: expired, answered, used or cancelled.
    ended: bool,
    expires_at: String,
    approved: bool,
    /// What the server shows as the commitment, when it lies about it.
    commitment: Option<String>,
    log: Vec<String>,
}

struct Script {
    state: Mutex<State>,
    now: Arc<AtomicI64>,
    approver_keys: DeviceKeys,
    new_keys: DeviceKeys,
}

fn answer(status: u16, body: Value) -> Result<Response, DeviceError> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).expect("json")
    };
    Ok(Response {
        status,
        retry_after: None,
        body: Zeroizing::new(bytes),
    })
}

fn gone() -> Result<Response, DeviceError> {
    answer(410, json!({"code": "approval_expired", "message": "x"}))
}

impl DeviceApi for Script {
    async fn send(&self, request: Request) -> Result<Response, DeviceError> {
        let mut s = self.state.lock().expect("lock");
        s.log.push(format!("{:?} {}", request.method, request.path));
        let body: Value = request
            .body
            .as_ref()
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or(Value::Null);
        let path = request.path.clone();
        let step = path.rsplit('/').next().unwrap_or_default().to_owned();
        match (request.method, path.as_str()) {
            (Method::Get, "/v1/devices") => answer(
                200,
                json!({"devices": [{
                    "id": NEW, "name": "Phone", "platform": "linux", "state": "pending",
                    "signing_key": b64(&self.new_keys.public().signing),
                    "agreement_key": b64(&self.new_keys.public().agreement),
                    "created_at": "2027-01-15T07:00:00Z", "approved_by": null,
                    "approval_signature": null, "current": false,
                }], "removals": []}),
            ),
            (Method::Post, "/v1/devices/approvals") => {
                s.create = Some(body.clone());
                let id = body["approval_id"].clone();
                answer(201, json!({"id": id, "expires_at": EXPIRES}))
            }
            (Method::Get, p) if p.starts_with("/v1/devices/approvals/") => {
                if s.ended {
                    return gone();
                }
                let create = s.create.clone().expect("created first");
                answer(
                    200,
                    json!({
                        "id": create["approval_id"], "expires_at": s.expires_at,
                        "created_at": create["created_at"], "approver_id": APPROVER,
                        "approver_signing_key": b64(&self.approver_keys.public().signing),
                        "approver_agreement_key": b64(&self.approver_keys.public().agreement),
                        "device_id": NEW,
                        "device_signing_key": b64(&self.new_keys.public().signing),
                        "device_agreement_key": b64(&self.new_keys.public().agreement),
                        "commitment": s.commitment.clone().map_or(create["commitment"].clone(), Value::from),
                        "device_nonce": b64(&[7u8; 32]),
                        "approver_nonce": s.approver_nonce, "signature": null,
                        "endorsement": null,
                    }),
                )
            }
            (Method::Post, _) if step == "reveal" => match s.reveal {
                Reveal::NetworkFails(n) if n > 0 => {
                    s.reveal = Reveal::NetworkFails(n - 1);
                    Err(DeviceError::Transport)
                }
                Reveal::AnswerLostOnce => {
                    s.approver_nonce = body["nonce"].as_str().map(str::to_owned);
                    s.reveal = Reveal::Works;
                    Err(DeviceError::Transport)
                }
                _ => {
                    s.approver_nonce = body["nonce"].as_str().map(str::to_owned);
                    answer(204, Value::Null)
                }
            },
            (Method::Post, _) if step == "confirm" => {
                if s.ended {
                    return gone();
                }
                s.approved = true;
                answer(204, Value::Null)
            }
            (Method::Post, _) if step == "cancel" => {
                if s.ended {
                    return gone();
                }
                s.ended = true;
                answer(204, Value::Null)
            }
            _ => answer(404, json!({"code": "not_found", "message": "x"})),
        }
    }
}

struct Fixed(Arc<AtomicI64>);

impl Clock for Fixed {
    fn now_secs(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

type Client = DeviceClient<Script, MemoryStore, Fixed>;

fn setup(reveal: Reveal) -> (Client, Engine) {
    let keys = DeviceKeys::generate().expect("keys");
    let copy = DeviceKeys::from_bytes(keys.to_bytes().as_slice()).expect("copy");
    let new_keys = DeviceKeys::generate().expect("keys");
    let store = MemoryStore::new();
    store
        .save(&StoredIdentity {
            device_keys: keys.to_bytes(),
            account_id: ACCOUNT.to_owned(),
            device_id: APPROVER.to_owned(),
            email: "a@example.test".to_owned(),
            session: Some(StoredSession {
                token: Zeroizing::new("token".to_owned()),
                expires_at: "2028-01-01T00:00:00Z".to_owned(),
            }),
            vault_key: Zeroizing::new([5u8; 32]),
        })
        .expect("save");
    let now = Arc::new(AtomicI64::new(NOW));
    let client = DeviceClient::new(
        Script {
            now: now.clone(),
            state: Mutex::new(State {
                create: None,
                reveal,
                approver_nonce: None,
                ended: false,
                expires_at: EXPIRES.to_owned(),
                approved: false,
                commitment: None,
                log: Vec::new(),
            }),
            approver_keys: copy,
            new_keys,
        },
        store,
        Fixed(now),
        ClientConfig {
            device_name: "Laptop".to_owned(),
            platform: DevicePlatform::Linux,
            app: None,
        },
    );
    let engine = Engine::new(keys, ACCOUNT, APPROVER).expect("engine");
    (client, engine)
}

fn log(client: &Client) -> Vec<String> {
    client.api().state.lock().expect("lock").log.clone()
}

fn count(client: &Client, needle: &str) -> usize {
    log(client).iter().filter(|l| l.contains(needle)).count()
}

async fn started(client: &Client, engine: &Engine) -> ApproverApproval {
    client.start_approval(engine, NEW).await.expect("start")
}

#[tokio::test]
async fn a_network_error_during_the_reveal_is_retried_and_never_cancels() {
    let (client, engine) = setup(Reveal::NetworkFails(2));
    let mut approval = started(&client, &engine).await;
    let state = client.approval_state(&mut approval).await.expect("state");
    assert!(matches!(state, ApproverState::Digits { .. }));
    assert_eq!(
        count(&client, "reveal"),
        3,
        "two failures, then it went through"
    );
    assert_eq!(count(&client, "cancel"), 0);
}

#[tokio::test]
async fn a_reveal_that_keeps_failing_reports_the_network_and_leaves_the_approval_open() {
    let (client, engine) = setup(Reveal::NetworkFails(100));
    let mut approval = started(&client, &engine).await;
    assert_eq!(
        client.approval_state(&mut approval).await.err(),
        Some(DeviceError::Transport)
    );
    assert_eq!(count(&client, "reveal"), 3, "a bounded number of tries");
    assert_eq!(
        count(&client, "cancel"),
        0,
        "a network failure does not cancel"
    );
    // The network is back: the same approval goes on.
    client.api().state.lock().expect("lock").reveal = Reveal::Works;
    let state = client.approval_state(&mut approval).await.expect("state");
    assert!(matches!(state, ApproverState::Digits { .. }));
    assert_eq!(count(&client, "cancel"), 0);
}

#[tokio::test]
async fn a_reveal_whose_answer_was_lost_is_not_sent_again_when_the_server_holds_it() {
    let (client, engine) = setup(Reveal::AnswerLostOnce);
    let mut approval = started(&client, &engine).await;
    let state = client.approval_state(&mut approval).await.expect("state");
    assert!(matches!(state, ApproverState::Digits { .. }));
    assert_eq!(
        count(&client, "reveal"),
        1,
        "the server already held the nonce"
    );
    assert_eq!(count(&client, "cancel"), 0);
}

#[tokio::test]
async fn the_digits_and_the_fingerprint_never_show_in_debug() {
    let (client, engine) = setup(Reveal::Works);
    let mut approval = started(&client, &engine).await;
    let state = client.approval_state(&mut approval).await.expect("state");
    let ApproverState::Digits {
        digits,
        fingerprint,
    } = &state
    else {
        panic!("digits");
    };
    for text in [format!("{state:?}"), format!("{state:#?}")] {
        assert!(!text.contains(digits.as_str()), "{text}");
        assert!(!text.contains(fingerprint.as_str()), "{text}");
        assert!(text.contains("Digits"), "{text}");
    }
    assert_eq!(format!("{:?}", ApproverState::Waiting), "Waiting");
}

#[tokio::test]
async fn the_time_left_comes_from_what_the_server_said_and_this_clock() {
    let (client, engine) = setup(Reveal::Works);
    let mut approval = started(&client, &engine).await;
    assert_eq!(client.time_left(&approval), Some(Duration::from_secs(600)));
    // Another 100 seconds pass on this device's clock.
    client.api().now.store(NOW + 100, Ordering::SeqCst);
    assert_eq!(client.time_left(&approval), Some(Duration::from_secs(500)));
    // The server's later answer refreshes it.
    client.api().state.lock().expect("lock").expires_at = "2027-01-15T08:20:00Z".to_owned();
    client.approval_state(&mut approval).await.expect("state");
    assert_eq!(client.time_left(&approval), Some(Duration::from_secs(1100)));
    // Past the end it is zero, never negative.
    client.api().now.store(NOW + 5000, Ordering::SeqCst);
    assert_eq!(client.time_left(&approval), Some(Duration::ZERO));
}

#[tokio::test]
async fn an_unreadable_expiry_shows_no_countdown() {
    let (client, engine) = setup(Reveal::Works);
    let mut approval = started(&client, &engine).await;
    // Neither an offset other than UTC nor garbage is guessed at; the last good time is kept.
    client.api().state.lock().expect("lock").expires_at = "2027-01-15T10:10:00+02:00".to_owned();
    client.approval_state(&mut approval).await.expect("state");
    assert_eq!(client.time_left(&approval), Some(Duration::from_secs(600)));
}

#[tokio::test]
async fn confirm_and_deny_on_an_approval_that_already_ended_never_approve() {
    // Confirm: the digits were shown, then the approval ended (expired, answered, denied).
    let (client, mut engine) = setup(Reveal::Works);
    let mut approval = started(&client, &engine).await;
    client.approval_state(&mut approval).await.expect("state");
    client.api().state.lock().expect("lock").ended = true;
    assert_eq!(
        client.confirm_approval(&mut engine, approval).await.err(),
        Some(DeviceError::ApprovalExpired)
    );
    assert!(!client.api().state.lock().expect("lock").approved);

    // Deny: nothing is sent to end an approval that is already over.
    let (client, engine) = setup(Reveal::Works);
    let approval = started(&client, &engine).await;
    client.api().state.lock().expect("lock").ended = true;
    assert_eq!(
        client.deny_approval(approval).await.err(),
        Some(DeviceError::ApprovalExpired)
    );
    assert_eq!(count(&client, "cancel"), 0);
    assert!(!client.api().state.lock().expect("lock").approved);

    // And an approval that was denied once cannot be denied or confirmed again.
    let (client, mut engine) = setup(Reveal::Works);
    let mut approval = started(&client, &engine).await;
    client.approval_state(&mut approval).await.expect("state");
    client.api().state.lock().expect("lock").ended = true;
    assert_eq!(
        client.approval_state(&mut approval).await.err(),
        Some(DeviceError::ApprovalExpired)
    );
    assert_eq!(
        client.confirm_approval(&mut engine, approval).await.err(),
        Some(DeviceError::ApprovalExpired)
    );
}

#[tokio::test]
async fn a_view_that_does_not_match_what_this_device_started_cancels_the_approval() {
    let (client, engine) = setup(Reveal::Works);
    let mut approval = started(&client, &engine).await;
    // The server shows another commitment than the one this device made: a real mismatch.
    client.api().state.lock().expect("lock").commitment = Some(b64(&[9u8; 32]));
    assert_eq!(
        client.approval_state(&mut approval).await.err(),
        Some(DeviceError::ApprovalMismatch)
    );
    assert_eq!(count(&client, "reveal"), 0, "nothing was revealed");
    assert_eq!(count(&client, "cancel"), 1, "a real mismatch cancels");
}
