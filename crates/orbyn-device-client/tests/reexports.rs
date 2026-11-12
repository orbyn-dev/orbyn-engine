//! The settings names and types are nameable from this crate alone, and they are the settings
//! crate's own.

use orbyn_device_client::{
    Accepted, PERSON_RECORD_ID, PERSON_SETTINGS, Rejected, Rule, Settings, SettingsError,
    ZONE_SETTINGS,
};

#[allow(dead_code)]
type Named = (
    Option<Settings>,
    Option<Accepted>,
    Option<Rejected>,
    Option<Rule>,
    Option<SettingsError>,
);

#[test]
fn the_zone_and_record_names_are_the_ones_the_app_syncs_under() {
    assert_eq!(ZONE_SETTINGS, "engineering.settings");
    assert_eq!(PERSON_SETTINGS, "person_settings");
    assert_eq!(PERSON_RECORD_ID, "person");
}

#[test]
fn settings_is_usable_through_this_crate() {
    let settings = Settings::default();
    assert!(format!("{settings:?}").contains("Settings"));
}
