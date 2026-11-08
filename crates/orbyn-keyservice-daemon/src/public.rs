//! The public API: five GET routes that let an app check the transparency log. No client
//! authentication; it runs on **its own plain-HTTP listener** (TLS ends at the tunnel in front of
//! it), apart from the mutual-TLS internal API, so no internal route can be reached through it:
//! this router is built from [`PUBLIC_ENDPOINTS`] alone and answers 404 to everything else.
//!
//! It reads only what the publisher published (`Store::published_*`): the newest head with its
//! cosignatures, and proofs in the same snapshot. No account id appears in any request or answer;
//! an account is reached only by its map key. What an answer reveals is written out in
//! `docs/key-service-3c.md` (*The public API*) and `docs/sharing.md`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, Query, Request, State as AxumState};
use axum::http::header::{
    self, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE,
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, ORIGIN, REFERRER_POLICY, RETRY_AFTER, VARY,
    X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get};
use axum::{Json, Router};
use orbyn_keyservice_client::{hex, unhex};
use orbyn_keyservice_server::{ChainEntry, PAGE, PublishedHead, Store, StoreError};
use orbyn_translog::{MapId, service_account_map_key};
use serde_json::{Value, json};

/// Which handler a route runs. [`router`] has one arm for each (a `match` with no wildcard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicHandler {
    Head,
    Consistency,
    Entries,
    Lookup,
    Keys,
}

/// Which hourly allowance a route counts against. Lookup and entries share one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allowance {
    Head,
    Consistency,
    Lookup,
    Keys,
}

impl Allowance {
    /// The `rate_events` action and the most requests per hour from one address block.
    pub fn limit(self) -> (&'static str, u32) {
        match self {
            Allowance::Head => ("public_head", HEAD_PER_HOUR),
            Allowance::Consistency => ("public_consistency", CONSISTENCY_PER_HOUR),
            Allowance::Lookup => ("public_lookup", LOOKUP_PER_HOUR),
            Allowance::Keys => ("public_keys", KEYS_PER_HOUR),
        }
    }
}

/// Requests an hour from one IPv4 /24 or IPv6 /64 block.
pub const HEAD_PER_HOUR: u32 = 600;
pub const CONSISTENCY_PER_HOUR: u32 = 60;
pub const LOOKUP_PER_HOUR: u32 = 60;
pub const KEYS_PER_HOUR: u32 = 60;

/// One row of the route table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicRoute {
    pub handler: PublicHandler,
    pub method: &'static str,
    pub path: &'static str,
    pub allowance: Allowance,
}

/// The route table, and the **only** thing [`router`] registers routes from; [`routes`] reports
/// it, so what a test lists is what is served. Every route is a GET.
pub const PUBLIC_ENDPOINTS: [PublicRoute; 5] = [
    PublicRoute {
        handler: PublicHandler::Head,
        method: "GET",
        path: "/v1/log/head",
        allowance: Allowance::Head,
    },
    PublicRoute {
        handler: PublicHandler::Consistency,
        method: "GET",
        path: "/v1/log/consistency",
        allowance: Allowance::Consistency,
    },
    PublicRoute {
        handler: PublicHandler::Entries,
        method: "GET",
        path: "/v1/log/entries",
        allowance: Allowance::Lookup,
    },
    PublicRoute {
        handler: PublicHandler::Lookup,
        method: "GET",
        path: "/v1/log/lookup/{service_public_key}",
        allowance: Allowance::Lookup,
    },
    PublicRoute {
        handler: PublicHandler::Keys,
        method: "GET",
        path: "/v1/keys",
        allowance: Allowance::Keys,
    },
];

pub fn routes() -> Vec<PublicRoute> {
    PUBLIC_ENDPOINTS.to_vec()
}

/// What `GET /v1/keys` says: what the service runs. Clients never trust it; they pin.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeysInfo {
    pub log_keys: Vec<(u32, [u8; 32])>,
    pub identity_keys: Vec<(u32, [u8; 32])>,
    pub witnesses: Vec<[u8; 32]>,
    pub threshold: usize,
}

/// How the public listener is set up.
#[derive(Clone, Debug, Default)]
pub struct PublicConfig {
    /// The browser origins that may call it (`ORBYN_KS_ALLOWED_ORIGINS`), compared exactly.
    pub allowed_origins: Vec<String>,
    /// The header a trusted proxy puts the client address in (`cf-connecting-ip` behind the
    /// tunnel); the last address in it is used. Without it the connection's own address is.
    pub client_ip_header: Option<HeaderName>,
    pub keys: KeysInfo,
    /// How long a request may take before it is answered 503. `None`: 30 seconds.
    pub request_timeout: Option<Duration>,
}

struct PublicState {
    store: Store,
    config: PublicConfig,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Retry-After for a service with nothing published yet.
const RETRY_AFTER_SECS: &str = "60";
const CSP: &str = "default-src 'none'; frame-ancestors 'none'";
const MAX_QUERY: usize = 512;

/// The public router, built from [`PUBLIC_ENDPOINTS`] alone.
pub fn router(store: Store, config: PublicConfig) -> Router {
    let state = Arc::new(PublicState { store, config });
    let mut router = Router::<Arc<PublicState>>::new();
    for endpoint in PUBLIC_ENDPOINTS {
        let handler: MethodRouter<Arc<PublicState>> = match endpoint.handler {
            PublicHandler::Head => get(head),
            PublicHandler::Consistency => get(consistency),
            PublicHandler::Entries => get(entries),
            PublicHandler::Lookup => get(lookup),
            PublicHandler::Keys => get(keys),
        };
        router = router.route(endpoint.path, handler.options(preflight));
    }
    router
        .fallback(not_found)
        // The timeout is inside the headers, so its 503 carries CSP, nosniff, Vary and CORS too.
        .layer(middleware::from_fn_with_state(state.clone(), time_limit))
        .layer(middleware::from_fn_with_state(state.clone(), headers))
        .with_state(state)
}

async fn time_limit(
    AxumState(state): AxumState<Arc<PublicState>>,
    request: Request,
    next: Next,
) -> Response {
    let limit = state.config.request_timeout.unwrap_or(REQUEST_TIMEOUT);
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

/// The headers every answer carries, and CORS for the allowed origins only.
async fn headers(
    AxumState(state): AxumState<Arc<PublicState>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| state.config.allowed_origins.iter().any(|a| a == o))
        .and_then(|o| HeaderValue::from_str(o).ok());
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    // The answer depends on the Origin header, so a cache must key on it.
    h.append(VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        h.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        if h.contains_key(ACCESS_CONTROL_MAX_AGE) {
            h.insert(
                ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET"),
            );
        }
    } else {
        // A preflight from an origin that is not allowed gets no CORS headers at all.
        h.remove(ACCESS_CONTROL_MAX_AGE);
    }
    response
}

async fn preflight() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
    response
}

fn error(status: StatusCode, code: &str) -> Response {
    let mut response = (status, Json(json!({ "error": code }))).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "not_found")
}

fn cached(body: Value, cache_control: &'static str) -> Response {
    let mut response = (StatusCode::OK, Json(body)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    response
}

/// Nothing is published yet: availability, not a verdict.
fn unpublished() -> Response {
    let mut response = error(StatusCode::SERVICE_UNAVAILABLE, "no_published_head");
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECS));
    response
}

fn store_error(error_: &StoreError) -> Response {
    match error_ {
        StoreError::Busy => error(StatusCode::SERVICE_UNAVAILABLE, "busy"),
        StoreError::Db(_) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        _ => {
            tracing::error!(event = "public_api_failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

/// The address block a client's allowance is counted for: an IPv4 /24 or an IPv6 /64 (an
/// IPv4-mapped IPv6 address counts as its IPv4).
pub fn address_block(ip: IpAddr) -> Vec<u8> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            vec![4, o[0], o[1], o[2]]
        }
        IpAddr::V6(v6) => {
            let mut out = vec![6];
            out.extend_from_slice(&v6.octets()[..8]);
            out
        }
    }
}

/// The client's address: the last address in the trusted header when one is configured and
/// present and readable, otherwise the connection's.
pub fn client_address(config: &PublicConfig, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    config
        .client_ip_header
        .as_ref()
        .and_then(|name| headers.get(name))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|last| last.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| peer.ip())
}

/// Counts the request against its allowance. `Err` is the answer to send.
async fn allow(
    state: &PublicState,
    allowance: Allowance,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Option<Response> {
    let (action, limit) = allowance.limit();
    let block = address_block(client_address(&state.config, headers, peer));
    match state
        .store
        .allow(action, &block, limit, crate::RATE_WINDOW_SECS)
        .await
    {
        Ok(true) => None,
        Ok(false) => {
            let mut response = error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("3600"));
            Some(response)
        }
        Err(e) => Some(store_error(&e)),
    }
}

fn hex_hashes(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(|h| hex(h)).collect()
}

fn head_json(head: &PublishedHead) -> Value {
    json!({
        "head": hex(&head.stored.head.encode()),
        "log_signature": hex(&head.stored.log_signature),
        "cosignatures": head.cosignatures.iter().map(|(key, cosignature)| json!({
            "witness_key": hex(key),
            "cosignature": hex(cosignature),
        })).collect::<Vec<_>>(),
    })
}

fn entry_json(entry: &ChainEntry) -> Value {
    json!({
        "index": entry.index,
        "chain_index": entry.chain_index,
        "entry": hex(&entry.entry),
        "inclusion_proof": hex_hashes(&entry.inclusion_proof),
    })
}

async fn head(
    AxumState(state): AxumState<Arc<PublicState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(refused) = allow(&state, Allowance::Head, &headers, peer).await {
        return refused;
    }
    match state.store.published_head().await {
        Ok(Some(head)) => cached(head_json(&head), "public, max-age=60"),
        Ok(None) => unpublished(),
        Err(e) => store_error(&e),
    }
}

async fn consistency(
    AxumState(state): AxumState<Arc<PublicState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    if let Some(refused) = allow(&state, Allowance::Consistency, &headers, peer).await {
        return refused;
    }
    let Some(query) = parse_query(&request) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let number = |name: &str| query.get(name).and_then(|v| v.parse::<u64>().ok());
    let (Some(from), Some(to)) = (number("from"), number("to")) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    if from == 0 || from > to {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    }
    match state.store.published_consistency(from, to).await {
        Ok(Some(proof)) => cached(
            json!({ "from": from, "to": to, "proof": hex_hashes(&proof) }),
            "public, max-age=31536000, immutable",
        ),
        Ok(None) => unpublished(),
        Err(StoreError::BadHead) => error(StatusCode::NOT_FOUND, "not_found"),
        Err(e) => store_error(&e),
    }
}

/// The query string as pairs, read once. A query over [`MAX_QUERY`] bytes, or one that does not
/// read, is `None`: a bad request.
fn parse_query(request: &Request) -> Option<std::collections::HashMap<String, String>> {
    match request.uri().query() {
        None => Some(Default::default()),
        Some(q) if q.len() > MAX_QUERY => None,
        Some(_) => Query::<std::collections::HashMap<String, String>>::try_from_uri(request.uri())
            .ok()
            .map(|q| q.0),
    }
}

/// The map an answer is about. Only the service-key map is served: it is the one a client looks
/// itself up in with its own service public key. The identity map has nothing to look up yet, so
/// `identity` is a bad request until its content lands.
fn parse_map(value: Option<&String>) -> Option<MapId> {
    match value.map(String::as_str) {
        None | Some("service") => Some(MapId::Service),
        _ => None,
    }
}

/// The map key of the account whose service public key this is (66 hex digits: 33 bytes). **The
/// service computes it; no route takes a map key**, so a map key learned from someone else's
/// absence proof opens nothing.
fn map_key_of(service_public_key: &str) -> Option<[u8; 32]> {
    unhex::<33>(service_public_key).map(|public| service_account_map_key(&public))
}

async fn entries(
    AxumState(state): AxumState<Arc<PublicState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    if let Some(refused) = allow(&state, Allowance::Lookup, &headers, peer).await {
        return refused;
    }
    let Some(query) = parse_query(&request) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let (Some(key), Some(map)) = (
        query.get("service_public_key").and_then(|k| map_key_of(k)),
        parse_map(query.get("map")),
    ) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let after = match query.get("after") {
        None => None,
        Some(text) => match text.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => return error(StatusCode::BAD_REQUEST, "bad_request"),
        },
    };
    match state.store.published_chain(map, &key, after, PAGE).await {
        Ok(Some(page)) => {
            let mut body = head_json(&page.head);
            body["map"] = json!(map_name(map));
            body["entries"] = Value::Array(page.entries.iter().map(entry_json).collect());
            body["next"] = json!(page.next);
            cached(body, "public, max-age=60")
        }
        Ok(None) => unpublished(),
        Err(e) => store_error(&e),
    }
}

fn map_name(map: MapId) -> &'static str {
    match map {
        MapId::Service => "service",
        MapId::Identity => "identity",
    }
}

async fn lookup(
    AxumState(state): AxumState<Arc<PublicState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(service_public_key): Path<String>,
    request: Request,
) -> Response {
    if let Some(refused) = allow(&state, Allowance::Lookup, &headers, peer).await {
        return refused;
    }
    let Some(query) = parse_query(&request) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let (Some(key), Some(map)) = (map_key_of(&service_public_key), parse_map(query.get("map")))
    else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    match state.store.published_lookup(map, &key).await {
        Ok(Some(view)) => {
            let Ok(proof) = view.proof.encode() else {
                return error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
            };
            let mut body = head_json(&view.head);
            body["map"] = json!(map_name(map));
            body["root"] = json!(hex(&view.root));
            body["proof"] = json!(hex(&proof));
            body["latest"] = view.latest.as_ref().map_or(Value::Null, entry_json);
            cached(body, "public, max-age=60")
        }
        Ok(None) => unpublished(),
        Err(e) => store_error(&e),
    }
}

async fn keys(
    AxumState(state): AxumState<Arc<PublicState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(refused) = allow(&state, Allowance::Keys, &headers, peer).await {
        return refused;
    }
    let k = &state.config.keys;
    let versioned = |keys: &[(u32, [u8; 32])]| -> Vec<Value> {
        keys.iter()
            .map(|(version, key)| json!({ "version": version, "public_key": hex(key) }))
            .collect()
    };
    cached(
        json!({
            "log_keys": versioned(&k.log_keys),
            "identity_keys": versioned(&k.identity_keys),
            "witnesses": k.witnesses.iter().map(|w| json!({ "key": hex(w) })).collect::<Vec<_>>(),
            "threshold": k.threshold,
        }),
        "public, max-age=300",
    )
}

/// Serves the router on `listener` over plain HTTP until the returned task is aborted. The
/// connection's address is passed to the handlers for the allowance.
pub fn serve(listener: tokio::net::TcpListener, router: Router) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    })
}

/// Reads `header` as a header name, lower-cased; `None` for text that is not one.
pub fn header_name(text: &str) -> Option<HeaderName> {
    header::HeaderName::from_bytes(text.trim().to_ascii_lowercase().as_bytes()).ok()
}

/// The public API's settings from the environment, checked before anything is bound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicSettings {
    /// `ORBYN_KS_PUBLIC_BIND`; without it there is no public API.
    pub bind: Option<(SocketAddr, String)>,
    pub client_ip_header: Option<HeaderName>,
    pub allowed_origins: Vec<String>,
}

impl PublicSettings {
    /// An error is the designed operator message, already formatted.
    pub fn parse(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |name: &str| lookup(name).filter(|v| !v.trim().is_empty());
        let bind = match get("ORBYN_KS_PUBLIC_BIND") {
            None => None,
            Some(text) => {
                let address = text
                    .trim()
                    .parse::<SocketAddr>()
                    .map_err(|_| crate::messages::public_bind_invalid())?;
                Some((address, text))
            }
        };
        let client_ip_header = match get("ORBYN_KS_CLIENT_IP_HEADER") {
            None => None,
            Some(text) => {
                Some(header_name(&text).ok_or_else(crate::messages::client_ip_header_invalid)?)
            }
        };
        let allowed_origins = get("ORBYN_KS_ALLOWED_ORIGINS")
            .map(|text| {
                text.split(',')
                    .map(|o| o.trim().to_owned())
                    .filter(|o| !o.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            bind,
            client_ip_header,
            allowed_origins,
        })
    }
}
