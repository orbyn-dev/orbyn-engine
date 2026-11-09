//! Device lists, removals and approval wire types.

use super::{DevicePlatform, DeviceState};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A device of the account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: DevicePlatform,
    pub state: DeviceState,
    pub signing_key: String,
    pub agreement_key: String,
    /// RFC 3339.
    pub created_at: String,
    /// The trusted device that approved this one; `None` for the first device.
    pub approved_by: Option<String>,
    /// The approver's signature over the `orbyn/device-approval/v1` message.
    /// Check it before trusting this device's keys.
    pub approval_signature: Option<String>,
    /// The approval that trusted this device; part of the signed message.
    #[serde(default)]
    #[ts(optional)]
    pub approval_id: Option<String>,
    /// Unix seconds the approver chose for that approval; part of the signed message.
    #[serde(default)]
    #[ts(optional, type = "number")]
    pub approval_created_at: Option<i64>,
    /// The SHA-256 of the endorsement that approval carried, base64url, when the approver's
    /// signature is the `orbyn/device-approval/v2` one that covers it; absent for an older
    /// approval, whose signature is the v1 one.
    #[serde(default)]
    #[ts(optional)]
    pub approval_endorsement_hash: Option<String>,
    /// True for the device making the request.
    pub current: bool,
}

/// `GET /v1/devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeviceList {
    pub devices: Vec<Device>,
    /// Signed records of removed devices; devices check them and stop trusting
    /// the removed device and every device only it approved.
    #[serde(default)]
    pub removals: Vec<DeviceRemoval>,
}

/// A removed device and the remover's signature over the
/// `orbyn/device-removal/v1` message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeviceRemoval {
    pub device_id: String,
    pub signing_key: String,
    pub agreement_key: String,
    pub removed_by: String,
    /// The remover's removal sequence, signed with the removal.
    #[ts(type = "number")]
    pub sequence: u64,
    pub signature: String,
}

/// `DELETE /v1/devices/{id}`: the remover's removal sequence and its
/// signature, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RemoveDevice {
    /// At most 2^53 - 1, so JavaScript reads it exactly.
    #[ts(type = "number")]
    pub sequence: u64,
    pub signature: String,
}

/// An approval as either of its devices sees it (`GET /v1/devices/current`
/// for the new device, `GET /v1/devices/approvals/{id}` for the approver).
/// Byte fields are base64url. Each optional field is set by one step, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PendingApproval {
    pub id: String,
    /// RFC 3339.
    pub expires_at: String,
    /// Unix seconds, chosen by the approver.
    #[ts(type = "number")]
    pub created_at: i64,
    pub approver_id: String,
    pub approver_signing_key: String,
    pub approver_agreement_key: String,
    pub device_id: String,
    pub device_signing_key: String,
    pub device_agreement_key: String,
    /// Step 1: the approver's commitment (32 bytes).
    pub commitment: String,
    /// Step 2: the new device's nonce (32 bytes).
    pub device_nonce: Option<String>,
    /// Step 3: the approver's nonce (32 bytes).
    pub approver_nonce: Option<String>,
    /// Step 4: the approver's signature, after the person confirmed on it.
    pub signature: Option<String>,
    /// Step 4: the approver's signed list of devices it trusts.
    pub endorsement: Option<String>,
}

/// `GET /v1/devices/current`: the device making the request, and the approval it
/// can answer, if a trusted device started one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CurrentDevice {
    pub device: Device,
    pub approval: Option<PendingApproval>,
    /// Sign-in asks for a second factor.
    pub totp_enabled: bool,
    /// Enrolled but not yet confirmed with a code.
    pub totp_pending: bool,
    /// RFC 3339: when the account will be deleted, if its deletion is scheduled. Show it on every
    /// device, with a way to cancel.
    #[serde(default)]
    #[ts(optional)]
    pub deletion_scheduled_at: Option<String>,
}

/// `POST /v1/devices/approvals`, step 1, from a trusted device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateApproval {
    /// A UUID the approver makes.
    pub approval_id: String,
    /// The device to approve: pending, or listed as trusted but without an
    /// approval the approver verifies.
    pub device_id: String,
    /// Unix seconds, within five minutes of the server's clock.
    #[ts(type = "number")]
    pub created_at: i64,
    /// The commitment to the approver's nonce (32 bytes, base64url).
    pub commitment: String,
}

/// The answer to [`CreateApproval`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalCreated {
    pub id: String,
    /// RFC 3339, ten minutes after creation.
    pub expires_at: String,
}

/// A nonce (32 bytes, base64url): step 2 from the new device
/// (`POST /v1/devices/approvals/{id}/nonce`) or step 3 from the approver
/// (`POST /v1/devices/approvals/{id}/reveal`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalNonce {
    pub nonce: String,
}

/// `POST /v1/devices/approvals/{id}/confirm`, step 4, from the approver after
/// the person confirmed the codes match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ConfirmApproval {
    /// Signature over the `orbyn/device-approval/v1` message, base64url.
    pub signature: String,
    /// The approver's signed list of devices it trusts, base64url, at most 16 KiB.
    #[serde(default)]
    #[ts(optional)]
    pub endorsement: Option<String>,
}

/// `POST /v1/devices/approvals/{id}/code`, step 5, from the new device: the six
/// digits it shows. One try.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalCode {
    pub code: String,
}
