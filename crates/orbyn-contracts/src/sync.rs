//! Sync WebSocket message wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A message a device sends on `/v1/sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum SyncClientMessage {
    /// The first message, within ten seconds of connecting.
    Auth { token: String },
}

/// A message the server sends on `/v1/sync`. None carries record data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum SyncServerMessage {
    /// Signed in; notices follow. Compare every zone's token now, since
    /// changes made while disconnected are not replayed.
    Ready { device_id: String },
    /// Another device changed the zone; fetch its changes.
    ZoneChanged { zone: String, token: String },
    /// Notices may have been missed; compare every zone's token.
    Resync,
    /// The connection closes after this.
    Error { code: String, message: String },
}
