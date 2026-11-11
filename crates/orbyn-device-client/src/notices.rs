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
}

impl Default for NoticeConfig {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(120),
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

/// `http` to `ws`, `https` to `wss`, and the sync path.
pub(crate) fn websocket_address(base: &str) -> Option<String> {
    let rest = base
        .strip_prefix("https://")
        .map(|r| ("wss", r))
        .or_else(|| base.strip_prefix("http://").map(|r| ("ws", r)))?;
    Some(format!(
        "{}://{}/v1/sync",
        rest.0,
        rest.1.trim_end_matches('/')
    ))
}

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
        match tokio_tungstenite::connect_async(address.as_str()).await {
            Ok((mut socket, _)) => {
                let auth = serde_json::to_string(&wire::SyncClientMessage::Auth {
                    token: token.to_string(),
                })
                .unwrap_or_default();
                if socket.send(Message::text(auth)).await.is_ok() {
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
            Err(_) => {
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
