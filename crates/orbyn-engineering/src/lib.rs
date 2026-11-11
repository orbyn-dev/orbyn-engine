//! Orbyn Engineering records. Pure and synchronous: the same code runs in the app, in tests and
//! in the browser as WebAssembly. The design is `docs/engineering.md`.

pub mod keys;
pub mod names;
pub mod settings;

pub use names::{PERSON_RECORD_ID, PERSON_SETTINGS, ZONE_SETTINGS, is_zone_name};
pub use settings::{
    Accepted, MAX_ENTRIES, MAX_KEY, MAX_RECORD_BYTES, MAX_VALUE_BYTES, NOT_SYNCED, Rejected, Rule,
    Settings, SettingsError, check_name,
};
