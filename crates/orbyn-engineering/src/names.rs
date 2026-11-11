//! The names Engineering gives to zones and record types. The engine accepts any zone name of 1 to
//! 64 characters without control characters, so these rules are ours, and they keep Engineering's
//! zones apart from the Planner's (`list:<id>`, `project:<id>`, `calendar:<id>` and `settings`).

/// The zone of the personal settings that follow the person.
pub const ZONE_SETTINGS: &str = "engineering.settings";

/// The record type of the one person-level settings record in [`ZONE_SETTINGS`].
pub const PERSON_SETTINGS: &str = "person_settings";
/// That record's id. There is one per account.
pub const PERSON_RECORD_ID: &str = "person";
/// The longest zone name the engine accepts.
const MAX_ZONE_NAME: usize = 64;
const PREFIX: &str = "engineering.";

fn is_slug(text: &str, max: usize) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && text.len() <= max
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether `name` is an Engineering zone name: `engineering.<kind>` or `engineering.<kind>:<id>`,
/// with a kind of lowercase letters, digits and `-` that starts with a letter, an id of lowercase
/// letters, digits and `-`, and at most 64 characters in all. A name made by another app, such as
/// the Planner's `settings`, is not one.
pub fn is_zone_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(PREFIX) else {
        return false;
    };
    if name.len() > MAX_ZONE_NAME {
        return false;
    }
    match rest.split_once(':') {
        None => is_slug(rest, MAX_ZONE_NAME),
        Some((kind, id)) => {
            is_slug(kind, MAX_ZONE_NAME)
                && !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engineering_zone_names_are_ours_and_distinct_from_the_planners() {
        assert!(is_zone_name(ZONE_SETTINGS));
        assert!(is_zone_name("engineering.profiles"));
        assert!(is_zone_name("engineering.workflow:a1-b2"));
        for other in [
            "settings",
            "list:3f2c",
            "project:3f2c",
            "calendar:3f2c",
            "engineering",
            "engineering.",
            "engineering.Settings",
            "engineering.1x",
            "engineering.x:",
            "engineering.x:A",
            "engineering.x y",
            "engineering.settings\n",
        ] {
            assert!(!is_zone_name(other), "{other:?}");
        }
        assert!(is_zone_name(&format!("engineering.{}", "a".repeat(52))));
        assert!(!is_zone_name(&format!("engineering.{}", "a".repeat(53))));
    }
}
