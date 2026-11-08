//! The public API against a real Postgres, real witnesses and a client that verifies what it is
//! served. Run with `--include-ignored`.

mod common;

use common::chain::Chain;
use orbyn_keyservice_client::hex;
use orbyn_keyservice_daemon::public::{self, KeysInfo, PublicConfig};
use orbyn_translog::map::verify as verify_map;
use orbyn_translog::merkle::{leaf_hash, verify_consistency, verify_inclusion};
use orbyn_translog::{
    Cosignature, Entry, Hash, Lookup, Proof, UnsignedHead, cosigned_enough, map_value,
    service_account_map_key,
};
use reqwest::StatusCode;
use serde_json::Value;

const MIN: u64 = 60 * 1000;

struct Served {
    url: String,
    http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
    /// When set, each request claims a new /24 in the trusted header (the server must be
    /// configured with `cf-connecting-ip`), so a test with many requests is not limited.
    rotate: std::sync::atomic::AtomicU32,
    rotating: bool,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Served {
    async fn start(c: &Chain, config: PublicConfig) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let task = public::serve(listener, public::router(c.state.store.clone(), config));
        Self {
            url,
            http: reqwest::Client::new(),
            task,
            rotate: std::sync::atomic::AtomicU32::new(0),
            rotating: false,
        }
    }

    async fn get(&self, path: &str) -> (StatusCode, reqwest::header::HeaderMap, Value) {
        self.get_with(path, &[]).await
    }

    async fn get_with(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, reqwest::header::HeaderMap, Value) {
        let mut request = self.http.get(format!("{}{path}", self.url));
        if self.rotating {
            let n = self
                .rotate
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            request = request.header("cf-connecting-ip", format!("10.{}.{}.1", n / 250, n % 250));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("answer");
        let status = response.status();
        let headers = response.headers().clone();
        let text = response.text().await.expect("body");
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, headers, body)
    }
}

fn config(c: &Chain, threshold: usize) -> PublicConfig {
    PublicConfig {
        allowed_origins: vec!["https://planner.example".to_owned()],
        client_ip_header: None,
        keys: KeysInfo {
            log_keys: vec![(c.log_version, c.log_public)],
            identity_keys: vec![(1, [9; 32])],
            witnesses: c.witnesses.iter().map(|w| w.public).collect(),
            threshold,
        },
        request_timeout: None,
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("a string");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn hash(value: &Value) -> Hash {
    bytes(value).try_into().expect("32 bytes")
}

fn hashes(value: &Value) -> Vec<Hash> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(hash)
        .collect()
}

/// What a client does with a head it was served: the log key signed it, and at least `threshold`
/// distinct pinned witnesses cosigned it.
fn verify_head(body: &Value, c: &Chain, threshold: usize) -> UnsignedHead {
    let head = UnsignedHead::decode(&bytes(&body["head"])).expect("a head");
    let signature: [u8; 64] = bytes(&body["log_signature"]).try_into().expect("64 bytes");
    assert!(
        head.verify(&c.log_public, &signature),
        "the log key signed it"
    );
    let pinned: Vec<[u8; 32]> = c.witnesses.iter().map(|w| w.public).collect();
    let cosignatures: Vec<Cosignature> = body["cosignatures"]
        .as_array()
        .expect("cosignatures")
        .iter()
        .map(|c| {
            let key: [u8; 32] = bytes(&c["witness_key"]).try_into().expect("key");
            let cosignature = Cosignature::decode(&bytes(&c["cosignature"])).expect("104 bytes");
            assert!(
                cosignature.verify(&key),
                "a cosignature verifies under its key"
            );
            cosignature
        })
        .collect();
    assert!(
        cosigned_enough(&head.hash(), &pinned, &cosignatures, threshold),
        "enough pinned witnesses cosigned it"
    );
    head
}

/// Removes the canonical bytes of every entry from an answer.
fn strip_entries(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("entry");
            map.values_mut().for_each(strip_entries);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_entries),
        _ => {}
    }
}

fn verify_entry(entry: &Value, head: &UnsignedHead) -> Entry {
    let bytes_ = bytes(&entry["entry"]);
    verify_inclusion(
        &leaf_hash(&bytes_),
        entry["index"].as_u64().expect("index"),
        head.size,
        &hashes(&entry["inclusion_proof"]),
        &head.log_root,
    )
    .expect("the entry is in the log of the head");
    Entry::decode(&bytes_).expect("a canonical entry")
}

/// A published log: three witnesses, threshold two, one account certified and published.
async fn published_log() -> (Chain, [u8; 33]) {
    let c = Chain::new(3).await;
    let public_key = c.key_for(1).await;
    let publisher = c.publisher(2);
    let cycle = publisher.publish_once().await.expect("cycle");
    assert!(matches!(
        cycle,
        orbyn_keyservice_daemon::publisher::Cycle::Published { .. }
    ));
    (c, public_key)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_public_listener_has_five_get_routes_and_no_internal_path_is_reachable_through_it() {
    let c = Chain::new(3).await;
    let served = Served::start(&c, config(&c, 2)).await;
    // The table, and what it was built from.
    let table: Vec<_> = public::routes()
        .iter()
        .map(|r| (r.method, r.path))
        .collect();
    assert_eq!(
        table,
        vec![
            ("GET", "/v1/log/head"),
            ("GET", "/v1/log/consistency"),
            ("GET", "/v1/log/entries"),
            ("GET", "/v1/log/lookup/{service_public_key}"),
            ("GET", "/v1/keys"),
        ]
    );
    // The internal API's own table, and some paths that are only near it: none is served here.
    let internal: Vec<String> = orbyn_keyservice_daemon::api::routes()
        .iter()
        .map(|r| r.path.replace("{account_id}", &hex(&[1u8; 16])))
        .chain(
            [
                "/internal",
                "/internal/",
                "/internal/v1",
                "/internal/v1/service-keys",
                "/internal/v1/service-keys/",
                "/healthz",
                "/health",
                "/ready",
                "/cancel",
                "/v1/service-keys",
                "/",
            ]
            .map(str::to_owned),
        )
        .collect();
    for path in &internal {
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"] {
            let request = served.http.request(
                method.parse().expect("method"),
                format!("{}{path}", served.url),
            );
            let status = request.send().await.expect("answer").status();
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path} answered {status}"
            );
            assert_ne!(status, StatusCode::OK, "{method} {path}");
        }
    }
    // The routes the table names take GET (and the preflight) and nothing else.
    let paths = [
        "/v1/log/head",
        "/v1/log/consistency?from=1&to=1",
        "/v1/log/entries?service_public_key=00",
        &format!("/v1/log/lookup/{}", hex(&[0u8; 33])),
        "/v1/keys",
    ];
    for path in paths {
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let status = served
                .http
                .request(
                    method.parse().expect("method"),
                    format!("{}{path}", served.url),
                )
                .send()
                .await
                .expect("answer")
                .status();
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        }
    }
    // A path that is no route's: exactly 404, with the same body for all.
    for path in [
        "/v1/log",
        "/v1/log/",
        "/v1/log/head/x",
        "/v1/log/lookup",
        "/v1/nope",
        "/%2e%2e/internal/v1/service-keys",
    ] {
        let (status, _, body) = served.get(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body["error"], "not_found");
    }
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn with_nothing_published_the_proof_routes_say_so_and_keys_still_answers() {
    let c = Chain::new(3).await;
    c.key_for(1).await;
    // A stored head with no cosignatures is not published either.
    let head = c
        .state
        .store
        .build_head(c.now(), c.log_version, None)
        .await
        .expect("head");
    c.state
        .store
        .commit_head(&head, &[1; 64])
        .await
        .expect("commit");
    let served = Served::start(&c, config(&c, 2)).await;
    for path in [
        "/v1/log/head".to_owned(),
        "/v1/log/consistency?from=1&to=1".to_owned(),
        format!("/v1/log/entries?service_public_key={}", hex(&[1; 33])),
        format!("/v1/log/lookup/{}", hex(&[1; 33])),
    ] {
        let (status, headers, body) = served.get(&path).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(body["error"], "no_published_head", "{path}");
        assert_eq!(headers["retry-after"], "60", "{path}");
        assert_eq!(headers["cache-control"], "no-store", "{path}");
    }
    let (status, _, body) = served.get("/v1/keys").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["threshold"], 2);
    assert_eq!(body["log_keys"][0]["version"], 1);
    assert_eq!(body["log_keys"][0]["public_key"], hex(&c.log_public));
    assert_eq!(body["witnesses"].as_array().expect("witnesses").len(), 3);
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_client_verifies_the_head_a_lookup_and_the_chain_from_the_served_bytes() {
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let map_key = service_account_map_key(&public_key);

    let (status, headers, body) = served.get("/v1/log/head").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "public, max-age=60");
    let head = verify_head(&body, &c, 2);
    assert_eq!(head.size, 1);

    // The lookup: head, map proof against the head's root, the newest entry in the log.
    let (status, headers, body) = served
        .get(&format!("/v1/log/lookup/{}?map=service", hex(&public_key)))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "public, max-age=60");
    let head = verify_head(&body, &c, 2);
    assert_eq!(hash(&body["root"]), head.service_map_root);
    let proof = Proof::decode(&bytes(&body["proof"])).expect("a proof");
    let value = match verify_map(&head.service_map_root, &map_key, &proof).expect("valid") {
        Lookup::Present(value) => value,
        Lookup::Absent => panic!("the key is certified"),
    };
    let latest = &body["latest"];
    let entry = verify_entry(latest, &head);
    assert_eq!(entry.map_key, map_key);
    assert_eq!(
        value,
        map_value(
            &entry.hash().expect("hash"),
            latest["chain_index"].as_u64().expect("i") + 1
        )
    );

    // The chain page agrees, with the same proofs.
    let (_, _, page) = served
        .get(&format!(
            "/v1/log/entries?service_public_key={}&map=service",
            hex(&public_key)
        ))
        .await;
    let page_head = verify_head(&page, &c, 2);
    assert_eq!(page_head, head);
    let entries = page["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(verify_entry(&entries[0], &page_head), entry);
    assert_eq!(page["next"], Value::Null);

    // Absence: a valid proof, no entry, and the same fields.
    let absent_public = [77u8; 33];
    let absent = service_account_map_key(&absent_public);
    let (status, _, body) = served
        .get(&format!("/v1/log/lookup/{}", hex(&absent_public)))
        .await;
    assert_eq!(status, StatusCode::OK);
    let head = verify_head(&body, &c, 2);
    let proof = Proof::decode(&bytes(&body["proof"])).expect("a proof");
    assert_eq!(
        verify_map(&head.service_map_root, &absent, &proof).expect("valid"),
        Lookup::Absent
    );
    assert_eq!(body["latest"], Value::Null);

    // Consistency between the first head and a later one.
    let first = head;
    c.advance(10 * MIN);
    c.key_for(2).await;
    c.publisher(2).publish_once().await.expect("cycle");
    let (_, _, newer) = served.get("/v1/log/head").await;
    let newer_head = verify_head(&newer, &c, 2);
    assert_eq!(newer_head.size, 2);
    let (status, headers, body) = served
        .get(&format!(
            "/v1/log/consistency?from={}&to={}",
            first.size, newer_head.size
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    verify_consistency(
        first.size,
        newer_head.size,
        &first.log_root,
        &newer_head.log_root,
        &hashes(&body["proof"]),
    )
    .expect("the log extends");
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_tampered_proof_a_wrong_key_and_too_few_cosignatures_all_fail_the_client() {
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let map_key = service_account_map_key(&public_key);
    let (_, _, body) = served
        .get(&format!("/v1/log/lookup/{}", hex(&public_key)))
        .await;
    let head = UnsignedHead::decode(&bytes(&body["head"])).expect("head");
    let entry_bytes = bytes(&body["latest"]["entry"]);
    let proof = hashes(&body["latest"]["inclusion_proof"]);
    let index = body["latest"]["index"].as_u64().expect("index");
    // The honest bytes verify; any one changed does not.
    assert!(
        verify_inclusion(
            &leaf_hash(&entry_bytes),
            index,
            head.size,
            &proof,
            &head.log_root
        )
        .is_ok()
    );
    let mut bad = entry_bytes.clone();
    *bad.last_mut().expect("bytes") ^= 1;
    assert!(verify_inclusion(&leaf_hash(&bad), index, head.size, &proof, &head.log_root).is_err());
    let mut wrong_root = head.log_root;
    wrong_root[0] ^= 1;
    assert!(
        verify_inclusion(
            &leaf_hash(&entry_bytes),
            index,
            head.size,
            &proof,
            &wrong_root
        )
        .is_err()
    );
    let map_proof = Proof::decode(&bytes(&body["proof"])).expect("proof");
    let mut other_root = head.service_map_root;
    other_root[5] ^= 1;
    assert!(
        verify_map(&other_root, &map_key, &map_proof).is_err()
            || verify_map(&other_root, &map_key, &map_proof)
                != verify_map(&head.service_map_root, &map_key, &map_proof)
    );
    // A log key the client did not pin does not verify the head's signature.
    let signature: [u8; 64] = bytes(&body["log_signature"]).try_into().expect("sig");
    assert!(head.verify(&c.log_public, &signature));
    assert!(!head.verify(&[3; 32], &signature));
    // Cosignatures: the served ones reach the threshold of two, but not three of three, and a
    // witness key the client did not pin counts for nothing.
    let pinned: Vec<[u8; 32]> = c.witnesses.iter().map(|w| w.public).collect();
    let cosignatures: Vec<Cosignature> = body["cosignatures"]
        .as_array()
        .expect("cosignatures")
        .iter()
        .map(|c| Cosignature::decode(&bytes(&c["cosignature"])).expect("cosignature"))
        .collect();
    assert!(cosigned_enough(&head.hash(), &pinned, &cosignatures, 2));
    assert!(!cosigned_enough(
        &head.hash(),
        &pinned,
        &cosignatures[..1],
        2
    ));
    assert!(!cosigned_enough(
        &head.hash(),
        &[[1; 32], [2; 32], [3; 32]],
        &cosignatures,
        2
    ));
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn what_is_stored_but_not_published_is_never_served() {
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let (_, _, first) = served.get("/v1/log/head").await;
    // A second key is certified; a head for it is stored, but only one witness is up of three, so
    // it cannot reach the threshold.
    c.witnesses[0].down();
    c.witnesses[1].down();
    c.advance(10 * MIN);
    let late_key = c.key_for(2).await;
    let cycle = c.publisher(2).publish_once().await.expect("cycle");
    assert!(matches!(
        cycle,
        orbyn_keyservice_daemon::publisher::Cycle::Unpublished { .. }
    ));
    assert_eq!(c.stored_heads().await, 2);
    // Still the first head, and the new key is in no lookup or chain.
    let (_, _, now) = served.get("/v1/log/head").await;
    assert_eq!(now["head"], first["head"]);
    let late_map_key = service_account_map_key(&late_key);
    let (_, _, lookup) = served
        .get(&format!("/v1/log/lookup/{}", hex(&late_key)))
        .await;
    assert_eq!(lookup["latest"], Value::Null);
    let head = UnsignedHead::decode(&bytes(&lookup["head"])).expect("head");
    let proof = Proof::decode(&bytes(&lookup["proof"])).expect("proof");
    assert_eq!(
        verify_map(&head.service_map_root, &late_map_key, &proof).expect("valid"),
        Lookup::Absent
    );
    let (_, _, page) = served
        .get(&format!(
            "/v1/log/entries?service_public_key={}",
            hex(&late_key)
        ))
        .await;
    assert!(page["entries"].as_array().expect("entries").is_empty());
    // The size is the published head's: a consistency proof to the stored head's size is not found.
    let (status, _, body) = served.get("/v1/log/consistency?from=1&to=2").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
    // The first key is still served as before.
    let (_, _, again) = served
        .get(&format!("/v1/log/lookup/{}", hex(&public_key)))
        .await;
    assert_eq!(again["head"], first["head"]);
    // The witnesses return; the next cycle publishes, and now the second key appears.
    c.witnesses[0].up();
    c.witnesses[1].up();
    c.advance(MIN);
    c.publisher(2).publish_once().await.expect("cycle");
    let (_, _, lookup) = served
        .get(&format!("/v1/log/lookup/{}", hex(&late_key)))
        .await;
    assert!(lookup["latest"].is_object());
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_cross_origin_contract_headers_and_cache_control() {
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let allowed = "https://planner.example";
    let map_key = hex(&public_key);
    let paths = [
        "/v1/log/head".to_owned(),
        "/v1/log/consistency?from=1&to=1".to_owned(),
        format!("/v1/log/entries?service_public_key={map_key}"),
        format!("/v1/log/lookup/{map_key}"),
        "/v1/keys".to_owned(),
    ];
    for path in &paths {
        // An allowed origin: its own origin back, never a wildcard, never credentials.
        let (status, headers, _) = served.get_with(path, &[("origin", allowed)]).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(headers["access-control-allow-origin"], allowed, "{path}");
        assert!(
            headers["vary"].to_str().expect("vary").contains("Origin"),
            "{path}"
        );
        assert!(
            headers.get("access-control-allow-credentials").is_none(),
            "{path}"
        );
        // Another origin, and none: no CORS headers (the public data is still returned).
        for other in [
            Some("https://evil.example"),
            Some("https://planner.example.evil.example"),
            Some("null"),
            None,
        ] {
            let extra: Vec<(&str, &str)> = other.map(|o| ("origin", o)).into_iter().collect();
            let (status, headers, _) = served.get_with(path, &extra).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(
                headers.get("access-control-allow-origin").is_none(),
                "{path} {other:?}"
            );
        }
        // Every answer: the headers that keep it from being anything but data.
        let (_, headers, _) = served.get(path).await;
        assert_eq!(
            headers["content-security-policy"],
            "default-src 'none'; frame-ancestors 'none'"
        );
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(headers["cross-origin-resource-policy"], "cross-origin");
        assert!(
            headers["content-type"]
                .to_str()
                .expect("type")
                .starts_with("application/json")
        );
        // The preflight: 204 for an allowed origin, with the method and max age; for another origin
        // 204 and nothing that lets a browser go on.
        let preflight = |origin: &str| {
            served
                .http
                .request(reqwest::Method::OPTIONS, format!("{}{path}", served.url))
                .header("origin", origin.to_owned())
                .header("access-control-request-method", "GET")
                .send()
        };
        let ok = preflight(allowed).await.expect("answer");
        assert_eq!(ok.status(), StatusCode::NO_CONTENT, "{path}");
        assert_eq!(ok.headers()["access-control-allow-origin"], allowed);
        assert_eq!(ok.headers()["access-control-allow-methods"], "GET");
        assert_eq!(ok.headers()["access-control-max-age"], "600");
        let bad = preflight("https://evil.example").await.expect("answer");
        assert_eq!(bad.status(), StatusCode::NO_CONTENT, "{path}");
        assert!(bad.headers().get("access-control-allow-origin").is_none());
        assert!(bad.headers().get("access-control-allow-methods").is_none());
    }
    // Cache-Control per route.
    let cache = |path: &str| {
        let path = path.to_owned();
        let served = &served;
        async move {
            served.get(&path).await.1["cache-control"]
                .to_str()
                .expect("cc")
                .to_owned()
        }
    };
    assert_eq!(cache("/v1/log/head").await, "public, max-age=60");
    assert_eq!(
        cache("/v1/log/consistency?from=1&to=1").await,
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        cache(&format!("/v1/log/entries?service_public_key={map_key}")).await,
        "public, max-age=60"
    );
    assert_eq!(
        cache(&format!("/v1/log/lookup/{map_key}")).await,
        "public, max-age=60"
    );
    assert_eq!(cache("/v1/keys").await, "public, max-age=300");
    // Errors are never cached.
    assert_eq!(cache("/v1/nope").await, "no-store");
    assert_eq!(cache("/v1/log/consistency?from=2&to=1").await, "no-store");
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn no_answer_carries_an_account_id_and_unknown_and_known_keys_have_one_shape() {
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let known = hex(&public_key);
    let unknown = hex(&[42u8; 33]);
    let mut shapes = Vec::new();
    for path in [
        "/v1/log/head".to_owned(),
        "/v1/log/consistency?from=1&to=1".to_owned(),
        format!("/v1/log/entries?service_public_key={known}"),
        format!("/v1/log/entries?service_public_key={unknown}"),
        format!("/v1/log/lookup/{known}"),
        format!("/v1/log/lookup/{unknown}"),
        "/v1/keys".to_owned(),
    ] {
        let (status, _, body) = served.get(&path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        // Anyone who knows an account's service public key can read that account's log entries,
        // which include its internal account id (the signed certification names it). So the id
        // is in the canonical `entry` bytes of that chain and in no other field: not in the head,
        // a proof, a key list or any other answer.
        let id = hex(&[1u8; 16]);
        let mut outside = body.clone();
        strip_entries(&mut outside);
        let text = outside.to_string();
        assert!(!text.contains(&id), "{path}");
        assert!(!text.contains("account"), "{path}");
        if path.contains(&known) {
            assert!(
                body.to_string().contains(&id) || path.contains("consistency"),
                "{path}: documents where the id is"
            );
        } else {
            assert!(!body.to_string().contains(&id), "{path}");
        }
        shapes.push((
            path,
            body.as_object()
                .expect("an object")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
        ));
    }
    // Known and unknown keys: the same status and the same fields in the answer.
    assert_eq!(shapes[2].1, shapes[3].1, "entries");
    assert_eq!(shapes[4].1, shapes[5].1, "lookup");
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn bad_requests_are_refused_and_a_chain_comes_in_pages_of_a_hundred() {
    let c = Chain::new(3).await;
    // One account with 150 entries (a chain of 150), published in one head: two pages.
    let public_key = [7u8; 33];
    append_chain(&c, &public_key, 150).await;
    c.publisher(2).publish_once().await.expect("cycle");
    let served = Served::start(&c, config(&c, 2)).await;
    let key = hex(&public_key);
    let mut seen = Vec::new();
    let mut after: Option<u64> = None;
    let mut pages = 0;
    loop {
        let path = match after {
            None => format!("/v1/log/entries?service_public_key={key}"),
            Some(a) => format!("/v1/log/entries?service_public_key={key}&after={a}"),
        };
        let (status, _, page) = served.get(&path).await;
        assert_eq!(status, StatusCode::OK);
        let head = verify_head(&page, &c, 2);
        let entries = page["entries"].as_array().expect("entries");
        assert!(entries.len() <= 100);
        for e in entries {
            verify_entry(e, &head);
            seen.push(e["chain_index"].as_u64().expect("chain index"));
        }
        pages += 1;
        match page["next"].as_u64() {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(pages, 2, "150 entries are a page of 100 and a page of 50");
    assert_eq!(seen.len(), 150);
    assert_eq!(
        seen,
        (0..seen.len() as u64).collect::<Vec<_>>(),
        "in order, no gaps, no repeats"
    );

    // Refusals.
    let bad = [
        "/v1/log/entries".to_owned(),
        "/v1/log/entries?service_public_key=zz".to_owned(),
        // A map key (32 bytes) or any other length is not a service public key (33 bytes).
        format!("/v1/log/entries?service_public_key={}", &key[..64]),
        format!("/v1/log/entries?service_public_key={}", &key[..62]),
        format!("/v1/log/entries?service_public_key={key}00"),
        format!("/v1/log/entries?service_public_key={key}&map=other"),
        // The identity map has nothing to look up by a service public key yet.
        format!("/v1/log/entries?service_public_key={key}&map=identity"),
        format!("/v1/log/lookup/{key}?map=identity"),
        format!("/v1/log/entries?service_public_key={key}&after=x"),
        format!("/v1/log/entries?service_public_key={key}&after=-1"),
        // A query over 512 bytes is refused, not read as empty.
        format!(
            "/v1/log/entries?service_public_key={key}&pad={}",
            "a".repeat(600)
        ),
        format!("/v1/log/lookup/{key}?pad={}", "a".repeat(600)),
        format!("/v1/log/consistency?from=1&to=1&pad={}", "a".repeat(600)),
        "/v1/log/lookup/abc".to_owned(),
        format!("/v1/log/lookup/{}", &key[..64]),
        format!("/v1/log/lookup/{key}00"),
        format!("/v1/log/lookup/{key}?map=other"),
        "/v1/log/consistency".to_owned(),
        "/v1/log/consistency?from=0&to=1".to_owned(),
        "/v1/log/consistency?from=3&to=2".to_owned(),
        "/v1/log/consistency?from=a&to=2".to_owned(),
        "/v1/log/consistency?from=1".to_owned(),
    ];
    for path in &bad {
        let (status, _, body) = served.get(path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(body["error"], "bad_request", "{path}");
    }
    let (status, _, _) = served.get("/v1/log/consistency?from=1&to=99999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn requests_are_limited_per_address_block_and_lookup_and_entries_share_one_allowance() {
    let (c, public_key) = published_log().await;
    let mut cfg = config(&c, 2);
    cfg.client_ip_header = public::header_name("CF-Connecting-IP");
    let served = Served::start(&c, cfg).await;
    let key = hex(&public_key);
    let from = |ip: &'static str| [("cf-connecting-ip", ip)];
    // 60 lookups and entries together from one /24; the 61st is refused, with Retry-After.
    for i in 0..60 {
        let path = if i % 2 == 0 {
            format!("/v1/log/lookup/{key}")
        } else {
            format!("/v1/log/entries?service_public_key={key}")
        };
        let ip = if i % 3 == 0 {
            "198.51.100.1"
        } else {
            "198.51.100.200"
        };
        let (status, _, _) = served.get_with(&path, &from(ip)).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    let (status, headers, body) = served
        .get_with(&format!("/v1/log/lookup/{key}"), &from("198.51.100.77"))
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(headers["retry-after"], "3600");
    let (status, _, _) = served
        .get_with(
            &format!("/v1/log/entries?service_public_key={key}"),
            &from("198.51.100.9"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "entries share the allowance"
    );
    // Another /24 is not limited; the other allowances (head, keys) are separate.
    let (status, _, _) = served
        .get_with(&format!("/v1/log/lookup/{key}"), &from("198.51.101.1"))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = served.get_with("/v1/log/head", &from("198.51.100.1")).await;
    assert_eq!(status, StatusCode::OK);
    // An IPv6 /64 is one block; an IPv4-mapped address counts as its IPv4.
    for i in 0..60 {
        let ip = format!("2001:db8:1:2:{i:x}::1");
        let (status, _, _) = served
            .get_with(
                "/v1/log/consistency?from=1&to=1",
                &[("cf-connecting-ip", &ip)],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "v6 request {i}");
    }
    let (status, _, _) = served
        .get_with(
            "/v1/log/consistency?from=1&to=1",
            &[("cf-connecting-ip", "2001:db8:1:2:ffff::9")],
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, _, _) = served
        .get_with(
            "/v1/log/consistency?from=1&to=1",
            &[("cf-connecting-ip", "2001:db8:1:3::1")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the next /64");
    // The last address in the header is the one counted; a forged first one buys nothing.
    let (status, _, _) = served
        .get_with(
            &format!("/v1/log/lookup/{key}"),
            &[("cf-connecting-ip", "203.0.113.5, 198.51.100.1")],
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn without_a_trusted_header_the_connections_address_is_counted_and_a_header_is_ignored() {
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let key = hex(&public_key);
    // Every request is from 127.0.0.1; a header that claims otherwise changes nothing.
    for i in 0..60 {
        let claim = format!("10.{}.0.1", i % 250);
        let (status, _, _) = served
            .get_with(
                &format!("/v1/log/lookup/{key}"),
                &[("cf-connecting-ip", &claim)],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{i}");
    }
    let (status, _, _) = served
        .get_with(
            &format!("/v1/log/lookup/{key}"),
            &[("cf-connecting-ip", "192.0.2.1")],
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // A configured header that is missing or unreadable falls back to the connection's address.
    let mut cfg = config(&c, 2);
    cfg.client_ip_header = public::header_name("cf-connecting-ip");
    let with_header = Served::start(&c, cfg).await;
    let (status, _, _) = with_header
        .get_with(
            &format!("/v1/log/lookup/{key}"),
            &[("cf-connecting-ip", "not an address")],
        )
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 127.0.0.1 allowance is spent"
    );
    c.finish().await;
}

#[test]
fn address_blocks_are_a_v4_24_or_a_v6_64_and_a_mapped_address_is_its_v4() {
    use std::net::IpAddr;
    let block = |text: &str| public::address_block(text.parse::<IpAddr>().expect("ip"));
    assert_eq!(block("192.0.2.1"), block("192.0.2.254"));
    assert_ne!(block("192.0.2.1"), block("192.0.3.1"));
    assert_eq!(block("2001:db8::1"), block("2001:db8::ffff:1"));
    assert_ne!(block("2001:db8:0:1::1"), block("2001:db8::1"));
    assert_eq!(block("::ffff:192.0.2.9"), block("192.0.2.1"));
    // A v4 block and a v6 block never collide.
    assert_ne!(block("0.0.0.0"), block("::"));
}

/// Appends a chain of `n` certification-shaped entries for the account whose service public key is
/// `public_key`, each naming the one before it.
async fn append_chain(c: &Chain, public_key: &[u8; 33], n: usize) {
    use orbyn_translog::{KIND_SERVICE_KEY, MapId};
    let map_key = service_account_map_key(public_key);
    let mut prev: Hash = [0; 32];
    for i in 0..n {
        let e = Entry {
            kind: KIND_SERVICE_KEY,
            map: MapId::Service,
            map_key,
            prev,
            time_ms: c.now(),
            fields: vec![(i % 251) as u8; 1],
        };
        prev = c.state.store.append(&e).await.expect("append").entry_hash;
    }
}

/// The map key a lookup of `public_key` ends its absence proof at (the neighbouring leaf), or
/// `None` when the proof is for a key that is present.
async fn neighbour_of(served: &Served, public_key: &[u8; 33]) -> Option<[u8; 32]> {
    let (status, _, body) = served
        .get(&format!("/v1/log/lookup/{}", hex(public_key)))
        .await;
    assert_eq!(status, StatusCode::OK);
    let head = UnsignedHead::decode(&bytes(&body["head"])).expect("head");
    let proof = Proof::decode(&bytes(&body["proof"])).expect("proof");
    let own = service_account_map_key(public_key);
    match verify_map(&head.service_map_root, &own, &proof).expect("valid") {
        Lookup::Present(_) => None,
        Lookup::Absent => match proof.end {
            orbyn_translog::End::Leaf { key, .. } => Some(key),
            orbyn_translog::End::Empty => None,
        },
    }
}

/// Every way a caller could try to open an account's entries with a map key it learned from an
/// absence proof. None may return an entry or a `latest`.
async fn assert_a_map_key_opens_nothing(served: &Served, map_key: &[u8; 32]) {
    let raw = hex(map_key);
    let mut paths = vec![
        format!("/v1/log/lookup/{raw}"),
        format!("/v1/log/entries?service_public_key={raw}"),
        format!("/v1/log/lookup/{raw}?map=service"),
    ];
    // As the tail of a 33-byte key, with every plausible prefix byte: it is then some other
    // service public key, whose own map key is a different hash.
    for prefix in ["00", "02", "03"] {
        paths.push(format!("/v1/log/lookup/{prefix}{raw}"));
        paths.push(format!("/v1/log/entries?service_public_key={prefix}{raw}"));
    }
    for path in paths {
        let (status, _, body) = served.get(&path).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::OK,
            "{path}: {status}"
        );
        assert!(body["latest"].is_null(), "{path}: an entry came back");
        assert!(
            body["entries"].as_array().is_none_or(|e| e.is_empty()),
            "{path}: entries came back"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_neighbours_map_key_from_an_absence_proof_opens_no_entries() {
    // Reviewer 26's finding as a regression: a lookup of a key that is not there ends at the
    // neighbouring leaf, which carries the neighbour's full map key. That key must open nothing.
    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let own = service_account_map_key(&public_key);
    let neighbour = neighbour_of(&served, &[200u8; 33])
        .await
        .expect("an absence proof");
    assert_eq!(neighbour, own, "the only account is the neighbour");
    assert_a_map_key_opens_nothing(&served, &neighbour).await;
    // The account itself is still reachable by its service public key.
    let (_, _, body) = served
        .get(&format!("/v1/log/lookup/{}", hex(&public_key)))
        .await;
    assert!(body["latest"].is_object());
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn walking_the_map_with_absence_proofs_finds_map_keys_and_no_entry_for_any_of_them() {
    let c = Chain::new(3).await;
    let accounts: Vec<[u8; 33]> = (1..=6u8).map(|n| [n; 33]).collect();
    for key in &accounts {
        append_chain(&c, key, 2).await;
    }
    c.publisher(2).publish_once().await.expect("cycle");
    let mut cfg = config(&c, 2);
    cfg.client_ip_header = public::header_name("cf-connecting-ip");
    let mut served = Served::start(&c, cfg).await;
    served.rotating = true;
    // Look up many keys that are not there, and collect every neighbour the proofs show.
    let wanted: std::collections::BTreeSet<[u8; 32]> =
        accounts.iter().map(service_account_map_key).collect();
    let mut found = std::collections::BTreeSet::new();
    for i in 0..400u32 {
        let mut probe = [0u8; 33];
        probe[1..5].copy_from_slice(&i.to_be_bytes());
        probe[0] = 2;
        if let Some(neighbour) = neighbour_of(&served, &probe).await {
            found.insert(neighbour);
        }
    }
    assert_eq!(
        found, wanted,
        "the walk learns every map key in the map (what is accepted)"
    );
    // And learns nothing more: none of them opens an entry.
    for map_key in &found {
        assert_a_map_key_opens_nothing(&served, map_key).await;
    }
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_request_that_times_out_still_carries_the_headers() {
    let (c, _) = published_log().await;
    let mut cfg = config(&c, 2);
    cfg.request_timeout = Some(std::time::Duration::ZERO);
    let served = Served::start(&c, cfg).await;
    let (status, headers, body) = served
        .get_with("/v1/log/head", &[("origin", "https://planner.example")])
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "unavailable");
    assert_eq!(
        headers["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert!(headers["vary"].to_str().expect("vary").contains("Origin"));
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://planner.example"
    );
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_clients_verifier_accepts_what_the_real_service_serves_and_refuses_a_wrong_pin() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use orbyn_client::{LogAnswers, ServiceKeyPins, ServiceKeyRefusal, verify_service_key};
    use orbyn_translog::verify::{Pins, Refusal};

    let (c, public_key) = published_log().await;
    let served = Served::start(&c, config(&c, 2)).await;
    let (_, _, lookup) = served
        .get(&format!("/v1/log/lookup/{}?map=service", hex(&public_key)))
        .await;
    let (_, _, entries) = served
        .get(&format!(
            "/v1/log/entries?service_public_key={}",
            hex(&public_key)
        ))
        .await;
    let account = [1u8; 16];
    let record = c
        .state
        .store
        .service_key(&account)
        .await
        .expect("read")
        .expect("a key");
    let uuid = {
        let h = hex(&account);
        format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    };
    let offered = orbyn_contracts::ServiceKeyCertification {
        account_id: uuid,
        identity_version: record.identity_version,
        public_key: B64.encode(record.public),
        statement_hash: B64.encode(orbyn_crypto::service_key_statement_hash(&record.statement)),
        signature: B64.encode(record.signature),
        entry_index: record.entry_index,
    };
    let pins = ServiceKeyPins {
        log: Pins {
            log_keys: vec![(c.log_version, c.log_public)],
            witnesses: c.witnesses.iter().map(|w| w.public).collect(),
            threshold: 2,
        },
        identity_keys: vec![(1, c.identity_public)],
    };
    let (lookup, entries) = (lookup.to_string(), entries.to_string());
    let answers = LogAnswers {
        lookup: &lookup,
        entry_pages: &[entries.as_str()],
        consistency: None,
    };
    // A device that already verified another key refuses this one (trust on first use otherwise).
    assert!(matches!(
        verify_service_key(
            &pins,
            account,
            &offered,
            &answers,
            Some(&[2; 33]),
            None,
            c.now()
        ),
        Err(ServiceKeyRefusal::KeyChanged)
    ));
    let verified = verify_service_key(&pins, account, &offered, &answers, None, None, c.now())
        .expect("the real service's bytes verify");
    assert_eq!(verified.public_key, public_key);
    assert_eq!(verified.entry_index, record.entry_index);

    // A device that pinned another identity, another log key or another witness set refuses.
    let mut other_identity = pins.clone();
    other_identity.identity_keys = vec![(1, [9; 32])];
    assert!(matches!(
        verify_service_key(
            &other_identity,
            account,
            &offered,
            &answers,
            None,
            None,
            c.now()
        ),
        Err(ServiceKeyRefusal::BadIdentitySignature)
    ));
    let mut other_log = pins.clone();
    other_log.log.log_keys = vec![(c.log_version, [9; 32])];
    assert!(matches!(
        verify_service_key(&other_log, account, &offered, &answers, None, None, c.now()),
        Err(ServiceKeyRefusal::Log(Refusal::BadLogSignature))
    ));
    let mut other_witnesses = pins.clone();
    other_witnesses.log.witnesses = vec![[7; 32], [8; 32], [9; 32]];
    assert!(matches!(
        verify_service_key(
            &other_witnesses,
            account,
            &offered,
            &answers,
            None,
            None,
            c.now()
        ),
        Err(ServiceKeyRefusal::Log(Refusal::NotEnoughWitnesses))
    ));
    // Two hours and a second later, the same bytes are stale.
    assert!(matches!(
        verify_service_key(
            &pins,
            account,
            &offered,
            &answers,
            None,
            None,
            c.now() + 2 * 3600 * 1000 + 1000
        ),
        Err(ServiceKeyRefusal::Log(Refusal::StaleHead))
    ));
}
