//! Health and error wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Whether a part of the engine is working.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ServiceState {
    Ok,
    Unavailable,
}

/// The engine's health, from `GET /health`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Health {
    pub status: ServiceState,
    pub version: String,
    pub database: ServiceState,
}

/// The body of every error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApiError {
    /// A stable, machine-readable reason, such as `not_found`.
    pub code: String,
    /// A short sentence a person can read.
    pub message: String,
}
