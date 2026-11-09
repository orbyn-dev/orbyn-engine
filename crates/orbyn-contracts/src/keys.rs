//! Zone-key envelope and service-key certification wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A zone key sealed by a trusted device to another trusted device of the same
/// account. The server stores the bytes and never opens them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewKeyEnvelope {
    pub recipient_device_id: String,
    /// The zone the key is for, 1 to 64 characters.
    pub zone: String,
    /// Names the zone key, base64url (16 bytes). A zone can have several.
    pub key_id: String,
    /// The wrapped key, base64url, at most 1 KiB decoded.
    pub envelope: String,
    /// Set when this key replaced another one of the zone.
    #[serde(default)]
    #[ts(optional)]
    pub rotation: Option<KeyRotation>,
}

/// The record of a zone key rotation, signed by the device that rotated it
/// under `orbyn/zone-key-rotation/v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyRotation {
    /// The key this one replaces, base64url (16 bytes).
    pub previous_key_id: String,
    pub signer_device_id: String,
    /// Base64url Ed25519 signature (64 bytes).
    pub signature: String,
}

/// `POST /v1/keychain/envelopes`: at most 100 envelopes from the session's device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PutKeyEnvelopes {
    pub envelopes: Vec<NewKeyEnvelope>,
    /// Zone keys sealed to the account's service key, stored in the same all-or-nothing batch
    /// (100 envelopes in all). Each names the statement hash of the certification it was sealed
    /// against: 409 `service_key_changed` if that is not the account's, 409 `protection_advanced`
    /// when the account's newest stored setting is Advanced, 409 `service_key_missing` before the
    /// server holds a certification (ask `GET /v1/keychain/service-key` first).
    #[serde(default)]
    #[ts(optional)]
    pub service_envelopes: Option<Vec<NewServiceEnvelope>>,
}

/// A zone key sealed to the account's service key (`wrap_key_p256`, label `orbyn/zone-key/v1`,
/// the account, the zone and the key id). The server never opens it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewServiceEnvelope {
    pub zone: String,
    /// Names the zone key, base64url (16 bytes).
    pub key_id: String,
    /// The wrapped key, base64url, at most 1 KiB decoded.
    pub envelope: String,
    /// SHA-256 of the certification statement the envelope was sealed against, base64url (32 bytes).
    pub statement_hash: String,
}

/// `GET /v1/keychain/service-key`: the account's service key as the key service certified it.
/// All of it is public. A device rebuilds the statement from the account id it knows, this key and
/// the identity version, checks the identity's signature with the identity key it pinned, and then
/// checks the transparency log itself before it escrows anything. 202 `service_key_pending` (an
/// `ApiError`) means the key exists but no published head holds its entry yet: ask again later.
/// 503 `key_service_unavailable`: none is configured, or it cannot be reached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ServiceKeyCertification {
    pub account_id: String,
    pub identity_version: u32,
    /// The compressed P-256 service public key, base64url (33 bytes).
    pub public_key: String,
    /// SHA-256 of the statement, base64url (32 bytes).
    pub statement_hash: String,
    /// The identity's Ed25519 signature over the statement, base64url (64 bytes).
    pub signature: String,
    /// The certification entry's position in the transparency log.
    #[ts(type = "number")]
    pub entry_index: u64,
}

/// A zone key some device holds an envelope for and the service holds none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MissingServiceKey {
    pub zone: String,
    /// Base64url (16 bytes).
    pub key_id: String,
}

/// `GET /v1/keychain/service-missing`: up to 100 pairs, in zone and key order. Send them, then
/// ask again until the list is empty. Empty under Advanced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ServiceMissingList {
    pub keys: Vec<MissingServiceKey>,
}

/// An envelope addressed to the device making the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyEnvelope {
    /// The device that sealed and signed it. Open it only if that device is
    /// one you trust.
    pub sender_device_id: String,
    pub zone: String,
    pub key_id: String,
    pub envelope: String,
    /// RFC 3339.
    pub created_at: String,
    #[serde(default)]
    #[ts(optional)]
    pub rotation: Option<KeyRotation>,
}

/// `GET /v1/keychain/envelopes`: every envelope for this device from a device
/// that is still trusted, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyEnvelopeList {
    pub envelopes: Vec<KeyEnvelope>,
}
