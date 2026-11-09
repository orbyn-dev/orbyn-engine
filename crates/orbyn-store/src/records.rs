//! Uploading and fetching records.

mod fetch;
mod model;
mod upload;

/// How long an operation id is remembered.
pub const OPERATION_TTL_DAYS: i32 = 7;
