//! Zone listing and deletion wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// `DELETE /v1/zones/{zone}`: the deleting device's proof, base64url, stored on
/// every tombstone the deletion makes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteZone {
    #[serde(default)]
    #[ts(optional)]
    pub proof: Option<String>,
}

/// A zone of the account's private database: one list, project or calendar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Zone {
    /// The client's name for it, 1 to 64 characters.
    pub zone: String,
    /// The zone's current change token. A device whose token differs fetches.
    pub token: String,
    /// Every record is a tombstone. `PUT` brings the zone back empty.
    pub deleted: bool,
    /// RFC 3339.
    pub created_at: String,
}

/// `GET /v1/zones`, deleted zones included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ZoneList {
    /// Up to 500 zones by name, deleted ones included.
    pub zones: Vec<Zone>,
    /// When there are more, pass this as `after` to `GET /v1/zones` for the next page.
    #[ts(optional)]
    pub next: Option<String>,
}

/// `DELETE /v1/zones/{zone}`: the token after every record became a tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ZoneDeleted {
    pub token: String,
}
