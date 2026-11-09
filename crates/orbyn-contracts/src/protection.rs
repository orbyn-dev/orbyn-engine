//! Protection settings and chain wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// How an account's keys are protected. Only a trusted device sets it, by signing the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProtectionLevel {
    Standard,
    Advanced,
}

/// One signed protection setting, as the server stores it. Settings form a chain: `prev` is the
/// SHA-256 of the previous setting's signed message (`orbyn_auth_client::protection_message`),
/// 32 zero bytes for the first, so a device can check that no setting was dropped, reordered or
/// replayed. Devices verify the signature themselves; the server's own checks are only a gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProtectionLink {
    pub level: ProtectionLevel,
    /// The first setting is 1. At most 2^53 - 1, so JavaScript reads it exactly.
    #[ts(type = "number")]
    pub seq: u64,
    /// Base64url, 32 bytes.
    pub prev: String,
    /// Unix seconds, as the device signed them.
    pub signed_at: i64,
    /// The trusted device that signed it.
    pub signer_device_id: String,
    /// Base64url Ed25519 signature (64 bytes) under `orbyn/protection/v1`.
    pub signature: String,
}

/// `POST /v1/keychain/protection`: the next setting, signed by the session's own device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SetProtection {
    pub level: ProtectionLevel,
    /// One more than the head's, or 1 for the first.
    #[ts(type = "number")]
    pub seq: u64,
    /// The hash of the head's signed message, or 32 zero bytes for the first (base64url).
    pub prev: String,
    /// Unix seconds; within five minutes of the server's clock.
    pub signed_at: i64,
    pub device_signature: String,
}

/// `GET /v1/keychain/protection?from=N`: settings from sequence `from` (default 1), oldest first,
/// at most 100 a page. `more` says to ask again from the last `seq` plus one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProtectionChain {
    pub links: Vec<ProtectionLink>,
    pub more: bool,
}

/// The 409 `protection_conflict` body: the setting did not fit the head (wrong sequence, wrong
/// `prev`, or a fork). `head` is the current newest setting, absent when none was ever set. A
/// device whose own setting is the head knows its earlier request went through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProtectionConflict {
    pub code: String,
    pub message: String,
    #[serde(default)]
    #[ts(optional)]
    pub head: Option<ProtectionLink>,
}
