//! The live notices stream (`/v1/sync`, a WebSocket): the server says a zone changed, and the host
//! runs a pass. A notice never carries record data. The stream reconnects with a growing, jittered
//! delay, answers the server's pings (the library does, when it reads) and treats a silent
//! connection as dead.

use crate::client::DeviceClient;
use crate::error::DeviceError;
use crate::{Clock, DeviceApi, KeyStore};
use futures_util::{SinkExt, StreamExt};
use orbyn_contracts as wire;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// What the stream tells the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// Connected and signed in. Compare every zone now: changes made while disconnected are not
    /// replayed.
    Connected,
    /// The connection ended; the stream reconnects by itself.
    Disconnected,
    /// Another device changed the zone.
    ZoneChanged { zone: String, token: String },
    /// Notices may have been missed.
    Resync,
    /// The server refused this connection (`unauthorized`, `too_many_connections`). The stream
    /// stops for `unauthorized`: sign in again and open a new one.
    Rejected { code: String },
}

/// How the stream reconnects.
#[derive(Clone, Copy, Debug)]
pub struct NoticeConfig {
    /// The delay before the first reconnect; it doubles each time up to `max_delay`.
    pub first_delay: Duration,
    pub max_delay: Duration,
    /// A connection that hears nothing for this long (the server pings) is dropped and redone.
    pub idle_timeout: Duration,
    /// The most time to connect and finish the WebSocket handshake.
    pub connect_timeout: Duration,
}

impl Default for NoticeConfig {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// The open stream. Dropping it closes the connection and stops the task.
pub struct Notices {
    rx: mpsc::Receiver<Notice>,
    task: JoinHandle<()>,
}

impl Notices {
    /// The next notice, or `None` once the stream has stopped.
    pub async fn next(&mut self) -> Option<Notice> {
        self.rx.recv().await
    }
}

impl Drop for Notices {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `https` to `wss`, and `http` to `ws` **only for a loopback IP literal**, plus the sync path.
/// Any other plain-text address is refused, whatever a transport reports as its base.
pub(crate) fn websocket_address(base: &str) -> Option<String> {
    let (scheme, rest) = if let Some(rest) = base.strip_prefix("https://") {
        ("wss", rest)
    } else if let Some(rest) = base.strip_prefix("http://")
        && crate::is_loopback_literal(base)
    {
        ("ws", rest)
    } else {
        return None;
    };
    Some(format!("{scheme}://{}/v1/sync", rest.trim_end_matches('/')))
}

/// The most a notice frame or message may hold. Notices are a few hundred bytes.
const MAX_FRAME: usize = 16 * 1024;

/// The delay before attempt number `attempt` (0 is the first), with up to a fifth of jitter.
pub(crate) fn backoff(config: &NoticeConfig, attempt: u32) -> Duration {
    let base = config
        .first_delay
        .saturating_mul(2u32.saturating_pow(attempt.min(16)));
    let mut random = [0u8; 2];
    let _ = getrandom::fill(&mut random);
    let jitter = f64::from(u16::from_be_bytes(random)) / f64::from(u16::MAX); // 0..=1
    base.mul_f64(0.8 + 0.4 * jitter).min(config.max_delay)
}

impl<A: DeviceApi, S: KeyStore, C: Clock> DeviceClient<A, S, C> {
    /// Opens the notices stream with this device's current session. It signs in with the token
    /// it has; when the token stops working the stream says `Rejected` and stops, and the host
    /// signs in again (`reauthenticate`) and opens a new one.
    pub fn notices(&self, config: NoticeConfig) -> Result<Notices, DeviceError> {
        let base = self.api.base_url().ok_or(DeviceError::InvalidInput(
            "this transport has no live stream",
        ))?;
        let address = websocket_address(base).ok_or(DeviceError::InvalidInput(
            "the engine address is not http or https",
        ))?;
        let identity = self.store.load()?.ok_or(DeviceError::NotSignedIn)?;
        let token = identity
            .session
            .as_ref()
            .ok_or(DeviceError::NotSignedIn)?
            .token
            .clone();
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(run(address, token, config, tx));
        Ok(Notices { rx, task })
    }
}

async fn run(
    address: String,
    token: zeroize::Zeroizing<String>,
    config: NoticeConfig,
    tx: mpsc::Sender<Notice>,
) {
    let mut attempt = 0u32;
    loop {
        let limits = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME));
        let connected = tokio::time::timeout(
            config.connect_timeout,
            tokio_tungstenite::connect_async_with_config(address.as_str(), Some(limits), false),
        )
        .await;
        match connected {
            Ok(Ok((mut socket, _))) => {
                // The sign-in message is written by hand into a wiped buffer, so the token is not
                // copied into a string that is dropped without being wiped. A token has only
                // URL-safe characters; anything else is not sent.
                let safe = token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'));
                let auth = zeroize::Zeroizing::new(if safe {
                    format!(r#"{{"type":"auth","token":"{}"}}"#, token.as_str())
                } else {
                    String::new()
                });
                if safe && socket.send(Message::text(auth.as_str())).await.is_ok() {
                    loop {
                        let next = tokio::time::timeout(config.idle_timeout, socket.next()).await;
                        let Ok(Some(Ok(message))) = next else { break };
                        let Message::Text(text) = message else {
                            // Pings are answered by the library as it reads; closes end the loop.
                            if matches!(message, Message::Close(_)) {
                                break;
                            }
                            continue;
                        };
                        let Ok(parsed) = serde_json::from_str::<wire::SyncServerMessage>(&text)
                        else {
                            continue;
                        };
                        let (notice, stop) = match parsed {
                            wire::SyncServerMessage::Ready { .. } => {
                                attempt = 0;
                                (Notice::Connected, false)
                            }
                            wire::SyncServerMessage::ZoneChanged { zone, token } => {
                                (Notice::ZoneChanged { zone, token }, false)
                            }
                            wire::SyncServerMessage::Resync => (Notice::Resync, false),
                            wire::SyncServerMessage::Error { code, .. } => {
                                let stop = code == "unauthorized";
                                (Notice::Rejected { code }, stop)
                            }
                        };
                        if tx.send(notice).await.is_err() {
                            return;
                        }
                        if stop {
                            return;
                        }
                    }
                }
                if tx.send(Notice::Disconnected).await.is_err() {
                    return;
                }
            }
            Ok(Err(_)) | Err(_) => {
                if tx.send(Notice::Disconnected).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(backoff(&config, attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_follows_the_scheme() {
        assert_eq!(
            websocket_address("https://api.orbyn.dev").as_deref(),
            Some("wss://api.orbyn.dev/v1/sync")
        );
        assert_eq!(
            websocket_address("http://127.0.0.1:8080/").as_deref(),
            Some("ws://127.0.0.1:8080/v1/sync")
        );
        assert_eq!(websocket_address("ftp://x"), None);
        // Plain text only to a loopback IP literal: a transport that reports http://anything gets
        // no stream, and a name such as localhost is not a literal.
        for refused in [
            "http://example.com",
            "http://localhost:8080",
            "http://192.168.1.2",
            "http://127.0.0.1.evil.example",
        ] {
            assert_eq!(websocket_address(refused), None, "{refused}");
        }
    }

    #[test]
    fn the_delay_grows_with_jitter_and_stops_at_the_cap() {
        let config = NoticeConfig::default();
        for attempt in 0..30 {
            let delay = backoff(&config, attempt);
            let base = Duration::from_secs(1u64 << attempt.min(6)).min(config.max_delay);
            assert!(
                delay >= base.mul_f64(0.79) && delay <= config.max_delay,
                "{attempt}: {delay:?}"
            );
        }
        assert!(backoff(&config, 40) <= config.max_delay);
    }
}
