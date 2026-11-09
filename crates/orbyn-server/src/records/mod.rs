//! `/v1` routes for the record store and the `/v1/sync` WebSocket. Each route
//! decodes the wire types, calls one operation of `orbyn_store::Store`, which
//! checks authorization itself, and maps the result.

use crate::AppState;
use crate::accounts::{Authed, service, time};
use axum::extract::rejection::QueryRejection;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use orbyn_contracts as wire;
use orbyn_core::Accounts;
use orbyn_core::accounts::{AccountError, DeviceState};
use orbyn_store::{Notice, Store, StoreError, Upload};
use serde::Deserialize;
use std::time::Duration;
use uuid::Uuid;

mod support;

use support::{AddressSlot, address_key, change, wire_record, wire_zone};
pub(crate) use support::{Answer, Body, Refusal, bytes, store};

/// The largest upload body: 4 MiB of record bytes in base64url, with room for
/// the JSON around them.
pub const UPLOAD_BODY_LIMIT: usize = 6 * 1024 * 1024;
/// How long a new `/v1/sync` connection may take to send its token.
const AUTH_WAIT: Duration = Duration::from_secs(3);
/// How often an open `/v1/sync` connection checks its session again.
/// How often a socket checks that its session and device are still valid, so
/// a removed device stops hearing notices within this time.
const RECHECK: Duration = Duration::from_secs(30);
/// How long one send may take before the peer is treated as gone.
const SEND_WAIT: Duration = Duration::from_secs(10);
/// Sockets still waiting for their auth message, across this replica.
static UNAUTHENTICATED: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4096);
/// Sockets one address (an IPv6 /64) may have waiting for their auth message,
/// so one client cannot take the shared slots from everyone else.
const WAITING_PER_ADDRESS: u32 = 8;
static WAITING: std::sync::Mutex<Option<std::collections::HashMap<[u8; 16], u32>>> =
    std::sync::Mutex::new(None);

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/zones", get(list_zones))
        .route("/v1/zones/{zone}", put(create_zone).delete(delete_zone))
        .route(
            "/v1/zones/{zone}/changes",
            get(fetch_changes)
                .post(upload)
                .layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)),
        )
        .route("/v1/sync", get(sync))
}

async fn create_zone(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
) -> Answer<(StatusCode, Json<wire::Zone>)> {
    let (zone, created) = store(&state)?.create_zone(&session, &zone).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(wire_zone(zone))))
}

#[derive(Deserialize)]
struct ZonesQuery {
    after: Option<String>,
}

async fn list_zones(
    State(state): State<AppState>,
    Authed(session): Authed,
    query: Result<Query<ZonesQuery>, QueryRejection>,
) -> Answer<Json<wire::ZoneList>> {
    let Query(query) = query.map_err(|_| Refusal::BadRequest)?;
    let (zones, next) = store(&state)?
        .list_zones(&session, query.after.as_deref())
        .await?;
    Ok(Json(wire::ZoneList {
        next,
        zones: zones.into_iter().map(wire_zone).collect(),
    }))
}

/// The body is optional: a `DeleteZone` with the deleting device's proof.
async fn delete_zone(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
    body: axum::body::Bytes,
) -> Answer<Json<wire::ZoneDeleted>> {
    let body: wire::DeleteZone = if body.is_empty() {
        wire::DeleteZone::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| Refusal::BadRequest)?
    };
    let proof = body.proof.as_deref().map(bytes).transpose()?;
    let token = store(&state)?
        .delete_zone(&session, &zone, proof.as_deref())
        .await?;
    Ok(Json(wire::ZoneDeleted {
        token: token.encode(),
    }))
}

async fn upload(
    State(state): State<AppState>,
    crate::accounts::Caller(client): crate::accounts::Caller,
    Authed(session): Authed,
    Path(zone): Path<String>,
    Body(body): Body<wire::UploadChanges>,
) -> Answer<Json<wire::UploadResult>> {
    let upload = Upload {
        operation_id: Uuid::parse_str(&body.operation_id).map_err(|_| Refusal::BadRequest)?,
        changes: body
            .changes
            .into_iter()
            .map(change)
            .collect::<Answer<_>>()?,
    };
    let result = store(&state)?
        .upload_from(
            &session,
            client.ip.map(|ip| address_key(Some(ip))),
            &zone,
            &upload,
        )
        .await?;
    Ok(Json(wire::UploadResult {
        token: result.token.encode(),
        modified_at: time(result.modified_at),
        records: result
            .records
            .into_iter()
            .map(|r| wire::SavedRecord {
                record_id: r.record_id,
                record_type: r.record_type,
                version: r.version,
                deleted: r.deleted,
            })
            .collect(),
        replayed: result.replayed,
    }))
}

#[derive(Deserialize)]
struct ChangesQuery {
    since: Option<String>,
    limit: Option<usize>,
}

async fn fetch_changes(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
    query: Result<Query<ChangesQuery>, QueryRejection>,
) -> Answer<Json<wire::ZoneChanges>> {
    let Query(query) = query.map_err(|_| Refusal::BadRequest)?;
    let changes = store(&state)?
        .fetch_changes(&session, &zone, query.since.as_deref(), query.limit)
        .await?;
    Ok(Json(wire::ZoneChanges {
        records: changes.records.into_iter().map(wire_record).collect(),
        token: changes.token.encode(),
        more: changes.more,
        zone_deleted: changes.zone_deleted,
    }))
}

/// `GET /v1/sync`. The token comes in the first message, not the URL or a
/// header, so it never lands in access logs. Browsers cannot set headers on a
/// WebSocket, and a page on another site cannot read the token to send it.
async fn sync(
    State(state): State<AppState>,
    crate::accounts::Caller(client): crate::accounts::Caller,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let (Ok(accounts), Ok(store)) = (service(&state), store(&state)) else {
        return Refusal::Unavailable.into_response();
    };
    let Ok(upgrade) = upgrade else {
        return Refusal::BadRequest.into_response();
    };
    // A bounded number of sockets may wait for their auth message, so opening
    // many without signing in cannot use up the server.
    let (Some(address), Ok(waiting)) =
        (AddressSlot::take(client.ip), UNAUTHENTICATED.try_acquire())
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(wire::ApiError {
                code: "too_many_attempts".to_owned(),
                message: "Too many connections are waiting; try again shortly.".to_owned(),
            }),
        )
            .into_response();
    };
    let (accounts, store) = (accounts.clone(), store.clone());
    let keepalive = state.sync_keepalive;
    upgrade
        .max_message_size(16 * 1024)
        .on_upgrade(move |socket| run_sync(socket, accounts, store, (waiting, address), keepalive))
}

/// Sends one message, giving up after [`SEND_WAIT`] so a peer that stops
/// reading cannot hold the connection's task.
async fn send(socket: &mut WebSocket, message: &wire::SyncServerMessage) -> bool {
    let Ok(text) = serde_json::to_string(message) else {
        return false;
    };
    matches!(
        tokio::time::timeout(SEND_WAIT, socket.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

/// Closes a silent socket with 1000 (normal), so its client reconnects and resyncs.
async fn close_idle(mut socket: WebSocket) {
    // Bounded like every other send: a half-dead peer with a full window would
    // otherwise hold the socket's cap place until the OS gives up on it.
    let _ = tokio::time::timeout(
        SEND_WAIT,
        socket.send(Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "idle".into(),
        }))),
    )
    .await;
}

/// Sends an error and closes with 1008 (policy violation).
async fn refuse(mut socket: WebSocket, code: &str, message: &str) {
    let _ = send(
        &mut socket,
        &wire::SyncServerMessage::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
    .await;
    let _ = tokio::time::timeout(
        SEND_WAIT,
        socket.send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: code.to_owned().into(),
        }))),
    )
    .await;
}

async fn run_sync(
    mut socket: WebSocket,
    accounts: Accounts,
    store: Store,
    waiting: (tokio::sync::SemaphorePermit<'static>, AddressSlot),
    keepalive: Duration,
) {
    let token = match tokio::time::timeout(AUTH_WAIT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            match serde_json::from_str::<wire::SyncClientMessage>(&text) {
                Ok(wire::SyncClientMessage::Auth { token }) => token,
                Err(_) => {
                    return refuse(socket, "invalid_request", "Send an auth message first.").await;
                }
            }
        }
        Ok(Some(Ok(_))) => {
            return refuse(socket, "invalid_request", "Send an auth message first.").await;
        }
        Ok(_) => return,
        Err(_) => return refuse(socket, "unauthorized", "No token was sent in time.").await,
    };
    let session = match accounts.authenticate(&token).await {
        Ok(session) => session,
        Err(_) => return refuse(socket, "unauthorized", "The session is not valid.").await,
    };
    drop(waiting);
    let mut feed = match store.feed(&session).await {
        Ok(feed) => feed,
        Err(StoreError::DeviceNotTrusted) => {
            return refuse(
                socket,
                "device_not_trusted",
                "Only a trusted device can do this.",
            )
            .await;
        }
        Err(StoreError::TooManyConnections) => {
            return refuse(
                socket,
                "too_many_connections",
                "This account has too many open connections.",
            )
            .await;
        }
        Err(_) => return refuse(socket, "internal", "Something went wrong on the server.").await,
    };
    let ready = wire::SyncServerMessage::Ready {
        device_id: session.device_id.to_string(),
    };
    if !send(&mut socket, &ready).await {
        return;
    }
    let mut recheck = tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
    // Keep-alive: a tunnel or proxy drops a connection that carries nothing for a while, and
    // this server otherwise sends nothing until a change arrives. Ping every `keepalive`; a
    // peer that has sent no frame at all (a pong or anything else) for two intervals is gone
    // or cut off, and is closed normally so its client reconnects and resyncs. Every way out
    // of this function drops the feed (the account's socket count) and the permits.
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + keepalive, keepalive);
    let mut last_heard = tokio::time::Instant::now();
    loop {
        tokio::select! {
            notice = feed.next() => {
                let message = match notice {
                    Some(Notice::ZoneChanged { zone, token }) => {
                        wire::SyncServerMessage::ZoneChanged { zone, token: token.encode() }
                    }
                    Some(Notice::Resync) => wire::SyncServerMessage::Resync,
                    None => break,
                };
                if !send(&mut socket, &message).await {
                    break;
                }
            }
            incoming = socket.recv() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                // Pings are answered by the WebSocket layer; other messages are ignored.
                // Any frame shows the peer is there.
                Some(Ok(_)) => last_heard = tokio::time::Instant::now(),
            },
            _ = ping.tick() => {
                if last_heard.elapsed() >= keepalive * 2 {
                    return close_idle(socket).await;
                }
                let sent = tokio::time::timeout(SEND_WAIT, socket.send(Message::Ping(Default::default()))).await;
                if !matches!(sent, Ok(Ok(()))) {
                    break;
                }
            },
            _ = recheck.tick() => match accounts.check_session(&token).await {
                Ok(now) if now.device_id == session.device_id
                    && now.device_state == DeviceState::Trusted => {}
                Ok(_) | Err(AccountError::Unauthorized) => {
                    return refuse(socket, "unauthorized", "The session ended.").await;
                }
                // A database hiccup keeps the connection; the next check decides.
                Err(_) => {}
            },
        }
    }
}

#[cfg(test)]
mod waiting_tests {
    use super::{AddressSlot, WAITING_PER_ADDRESS, address_key};
    use std::net::IpAddr;

    #[test]
    fn one_address_gets_a_bounded_number_of_waiting_slots() {
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        let mut slots: Vec<AddressSlot> = (0..WAITING_PER_ADDRESS)
            .map(|_| AddressSlot::take(Some(ip)).expect("slot"))
            .collect();
        assert!(
            AddressSlot::take(Some(ip)).is_none(),
            "the next one is refused"
        );
        let other: IpAddr = "203.0.113.10".parse().expect("ip");
        assert!(
            AddressSlot::take(Some(other)).is_some(),
            "another address is unaffected"
        );
        slots.pop();
        assert!(
            AddressSlot::take(Some(ip)).is_some(),
            "a slot comes back when dropped"
        );
    }

    #[test]
    fn ipv6_addresses_count_by_their_slash_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().expect("ip");
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().expect("ip");
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        assert_eq!(address_key(Some(a)), address_key(Some(b)));
        assert_ne!(address_key(Some(a)), address_key(Some(c)));
    }

    #[test]
    fn ipv4_mapped_addresses_count_as_their_ipv4_address() {
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().expect("ip");
        let plain: IpAddr = "203.0.113.9".parse().expect("ip");
        let other: IpAddr = "::ffff:198.51.100.7".parse().expect("ip");
        assert_eq!(address_key(Some(mapped)), address_key(Some(plain)));
        assert_ne!(address_key(Some(mapped)), address_key(Some(other)));
        assert_ne!(address_key(Some(mapped)), address_key(None));
    }
}
