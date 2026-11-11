//! The person's settings: one record in the `engineering.settings` zone, as fields that merge one
//! by one. Plain fields, the two sets and the keybindings follow the rules in `docs/engineering.md`.

use crate::keys::{self, Class, Kind, SET_LISTS, Spec};
use orbyn_sync::{Fields, Stamp, merge_remote};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The longest field name, in bytes.
pub const MAX_KEY: usize = 64;
/// The most a field's value may take, as JSON.
pub const MAX_VALUE_BYTES: usize = 8 * 1024;
/// The most the whole record may take, as the JSON of its fields with their stamps. It is enforced
/// on **local writes only**: a merge from another device is always applied, so devices converge
/// even when two of them each filled the record.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// A removal (a `null` field) older than this, measured against the stamp of a local write, is
/// dropped by that write: 90 days.
pub const COMPACT_AFTER_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// The most entries of a list: members of a set, keybinding rules and `model_order`.
pub const MAX_ENTRIES: usize = 500;

pub use crate::keys::NOT_SYNCED;

/// Why a name or value was refused. Never carries any of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// The name is not 1 to 64 of `a-z 0-9 _ . :`, starts with `_` (orbyn-sync's own fields, such
    /// as `_deleted`, do), or is reserved.
    #[error("the key is not valid")]
    InvalidKey,
    /// The setting stays on the device it was made on.
    #[error("this setting is never synced")]
    NotSynced,
    /// A value over 8 KiB, a write that would take the record over 64 KiB, or a list over 500
    /// entries.
    #[error(
        "too large: a value is limited to 8 KiB, the record to 64 KiB and a list to 500 entries"
    )]
    TooLarge,
    /// The key is not one this version has, so it cannot be written.
    #[error("this version has no such setting")]
    UnknownKey,
    /// The value is not what the setting holds.
    #[error("the value is not valid for this setting")]
    InvalidValue,
    /// A change stamped too far ahead of this device's clock.
    #[error("the change is stamped too far ahead")]
    TooFarAhead,
}

/// A name that is allowed as a field name at all: 1 to 64 of `a-z 0-9 _ . :`, not starting with `_`
/// (so a peer cannot write orbyn-sync's `_deleted` and make the record read as deleted), and not
/// on the [`NOT_SYNCED`] list.
pub fn check_name(name: &str) -> Result<Class, SettingsError> {
    let chars_ok = !name.is_empty()
        && !name.starts_with('_')
        && name.len() <= MAX_KEY
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':')
        });
    if !chars_ok {
        return Err(SettingsError::InvalidKey);
    }
    if keys::NOT_SYNCED.contains(&name) {
        return Err(SettingsError::NotSynced);
    }
    keys::classify(name).ok_or(SettingsError::InvalidKey)
}

fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

fn record_len(fields: &Fields) -> usize {
    serde_json::to_vec(fields).map_or(usize::MAX, |bytes| bytes.len())
}

/// A keybinding rule. `remove` takes a default binding away, as the app's list says; it is not
/// the removal of the rule from the synced record, which is a `null` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub key: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove: bool,
}

impl Rule {
    fn from_value(value: &Value) -> Option<Rule> {
        let rule: Rule = serde_json::from_value(value.clone()).ok()?;
        let ok = (1..=128).contains(&rule.key.len())
            && (1..=256).contains(&rule.command.len())
            && rule
                .when
                .as_ref()
                .is_none_or(|w| (1..=512).contains(&w.len()));
        ok.then_some(rule)
    }

    fn field(&self) -> String {
        keys::keybinding_field(&self.key, self.when.as_deref())
    }
}

fn valid_element(value: &Value) -> Option<&str> {
    value.as_str().filter(|id| (1..=512).contains(&id.len()))
}

fn valid_plain(spec: &Spec, value: &Value) -> bool {
    match spec.kind {
        Kind::Text => value.is_string(),
        Kind::Enum(options) => value.as_str().is_some_and(|v| options.contains(&v)),
        Kind::EnumOrThemeId(options) => value
            .as_str()
            .is_some_and(|v| options.contains(&v) || keys::is_theme_id(v)),
        Kind::Bool => value.is_boolean(),
        Kind::Number => value
            .as_f64()
            .is_some_and(|n| n.is_finite() && n > 0.0 && n <= 10.0),
        Kind::Order => value
            .as_array()
            .is_some_and(|list| list.len() <= MAX_ENTRIES && list.iter().all(Value::is_string)),
    }
}

/// The settings record. It wraps the merged fields exactly as stored, so a field this version does
/// not know, from a newer app, is kept and passed on untouched.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    fields: Fields,
}

/// A field that was refused from another device, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub name: String,
    pub error: SettingsError,
}

/// The result of [`Settings::accept_remote`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accepted {
    pub rejected: Vec<Rejected>,
}

/// A name that never leaves the device: a setting on the [`NOT_SYNCED`] list, or a name that starts
/// with `_` (orbyn-sync's own fields, such as `_deleted`).
fn stays_local(name: &str) -> bool {
    name.starts_with('_') || keys::NOT_SYNCED.contains(&name)
}

impl Settings {
    /// Wraps the fields of a stored record. A record stored by an earlier version may hold a field
    /// that never syncs (or an `_` name); such fields are **dropped here**, so they are never
    /// uploaded again and nothing in this record reads them. The app keeps its own local copy of
    /// those settings outside this record.
    pub fn from_fields(mut fields: Fields) -> Self {
        fields.0.retain(|name, _| !stays_local(name));
        Self { fields }
    }

    /// The merged fields, to store and upload. None of them is a setting that never syncs or a
    /// name that starts with `_`: [`Settings::from_fields`] and [`Settings::accept_remote`] keep
    /// them out, so whatever this returns is safe to send.
    pub fn fields(&self) -> &Fields {
        &self.fields
    }

    pub fn into_fields(self) -> Fields {
        self.fields
    }

    /// The value of a plain setting: what was set, else its default. A value this version cannot
    /// read (a value a newer app added to an enum, a wrong type) reads as the default and stays in
    /// the record as it was.
    pub fn get(&self, key: &str) -> Result<Value, SettingsError> {
        let Class::Plain(Some(spec)) = check_name(key)? else {
            return Err(SettingsError::UnknownKey);
        };
        Ok(self
            .fields
            .get(key)
            .filter(|value| !value.is_null() && valid_plain(spec, value))
            .cloned()
            .unwrap_or_else(|| spec.default_value()))
    }

    /// The raw value of any field, including one from a newer version.
    pub fn raw(&self, name: &str) -> Option<&Value> {
        self.fields.get(name).filter(|value| !value.is_null())
    }

    /// The names of fields from a newer version: plain fields this version has no spec for.
    pub fn unknown(&self) -> Vec<&str> {
        self.fields
            .0
            .keys()
            .filter(|name| matches!(check_name(name), Ok(Class::Plain(None))))
            .map(String::as_str)
            .collect()
    }

    /// Stores the result of a local write made at `stamp`: first drops the removals older than
    /// [`COMPACT_AFTER_MS`] before it, then refuses it if the record would pass the cap **and**
    /// grow. A write that does not grow the record (a removal, a reset) is always allowed, so a
    /// record that merged past the cap can always be brought back under it.
    fn commit(&mut self, mut next: Fields, stamp: Stamp) -> Result<(), SettingsError> {
        next.0.retain(|_, field| {
            !(field.value.is_null()
                && field.stamp.millis.saturating_add(COMPACT_AFTER_MS) < stamp.millis)
        });
        let size = record_len(&next);
        if size > MAX_RECORD_BYTES && size > record_len(&self.fields) {
            return Err(SettingsError::TooLarge);
        }
        self.fields = next;
        Ok(())
    }

    /// Sets a plain setting. `null` puts it back to its default.
    pub fn set(&mut self, key: &str, value: Value, stamp: Stamp) -> Result<(), SettingsError> {
        let Class::Plain(Some(spec)) = check_name(key)? else {
            return Err(SettingsError::UnknownKey);
        };
        if json_len(&value) > MAX_VALUE_BYTES {
            return Err(SettingsError::TooLarge);
        }
        let list_too_long = match &value {
            Value::Array(list) => list.len() > MAX_ENTRIES,
            Value::Object(map) => map.len() > MAX_ENTRIES,
            _ => false,
        };
        if list_too_long {
            return Err(SettingsError::TooLarge);
        }
        if !value.is_null() && !valid_plain(spec, &value) {
            return Err(SettingsError::InvalidValue);
        }
        let mut next = self.fields.clone();
        next.set(key, value, stamp);
        self.commit(next, stamp)
    }

    /// The members of a set, sorted.
    pub fn members(&self, list: &str) -> Result<Vec<String>, SettingsError> {
        if !SET_LISTS.contains(&list) {
            return Err(SettingsError::UnknownKey);
        }
        let prefix = format!("{list}.");
        let mut out: Vec<String> = self
            .fields
            .0
            .iter()
            .filter(|(name, _)| name.starts_with(&prefix))
            .filter_map(|(name, field)| {
                let id = valid_element(&field.value)?;
                (keys::element_field(list, id) == *name).then(|| id.to_owned())
            })
            .collect();
        out.sort();
        out.truncate(MAX_ENTRIES);
        Ok(out)
    }

    /// Adds `id` to a set: its field takes the id as its value.
    pub fn add(&mut self, list: &str, id: &str, stamp: Stamp) -> Result<(), SettingsError> {
        let members = self.members(list)?;
        if !(1..=512).contains(&id.len()) {
            return Err(SettingsError::InvalidValue);
        }
        if members.len() >= MAX_ENTRIES && !members.iter().any(|m| m == id) {
            return Err(SettingsError::TooLarge);
        }
        let mut next = self.fields.clone();
        next.set(
            &keys::element_field(list, id),
            Value::String(id.to_owned()),
            stamp,
        );
        self.commit(next, stamp)
    }

    /// Removes `id` from a set: its field becomes `null` with its own stamp, so a later add on
    /// another machine is a later edit and wins, and an earlier one does not bring it back.
    pub fn remove(&mut self, list: &str, id: &str, stamp: Stamp) -> Result<(), SettingsError> {
        self.members(list)?;
        let mut next = self.fields.clone();
        next.set(&keys::element_field(list, id), Value::Null, stamp);
        self.commit(next, stamp)
    }

    /// The keybinding rules, sorted by key, then `when`.
    pub fn keybindings(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = self
            .fields
            .0
            .iter()
            .filter(|(name, _)| matches!(keys::classify(name), Some(Class::Keybinding)))
            .filter_map(|(name, field)| {
                let rule = Rule::from_value(&field.value)?;
                (rule.field() == *name).then_some(rule)
            })
            .collect();
        rules.sort_by(|a, b| (&a.key, &a.when).cmp(&(&b.key, &b.when)));
        rules.truncate(MAX_ENTRIES);
        rules
    }

    /// Adds or replaces the rule for its key and `when`.
    pub fn bind(&mut self, rule: &Rule, stamp: Stamp) -> Result<(), SettingsError> {
        let value = serde_json::to_value(rule).map_err(|_| SettingsError::InvalidValue)?;
        if Rule::from_value(&value).is_none() {
            return Err(SettingsError::InvalidValue);
        }
        let name = rule.field();
        let exists = self.fields.get(&name).is_some_and(|v| !v.is_null());
        if !exists && self.keybindings().len() >= MAX_ENTRIES {
            return Err(SettingsError::TooLarge);
        }
        let mut next = self.fields.clone();
        next.set(&name, value, stamp);
        self.commit(next, stamp)
    }

    /// Removes the rule for `key` and `when` from the record: its field becomes `null`.
    pub fn unbind(
        &mut self,
        key: &str,
        when: Option<&str>,
        stamp: Stamp,
    ) -> Result<(), SettingsError> {
        let mut next = self.fields.clone();
        next.set(&keys::keybinding_field(key, when), Value::Null, stamp);
        self.commit(next, stamp)
    }

    /// What is wrong with one incoming field, if anything that makes it unfit to keep.
    fn refuse(name: &str, value: &Value) -> Option<SettingsError> {
        let class = match check_name(name) {
            Ok(class) => class,
            Err(error) => return Some(error),
        };
        if json_len(value) > MAX_VALUE_BYTES {
            return Some(SettingsError::TooLarge);
        }
        match class {
            // A removal needs no derivation; an element or rule must be the one its name says.
            Class::Element(list) if !value.is_null() => valid_element(value)
                .filter(|id| keys::element_field(list, id) == name)
                .is_none()
                .then_some(SettingsError::InvalidValue),
            Class::Keybinding if !value.is_null() => Rule::from_value(value)
                .filter(|rule| rule.field() == name)
                .is_none()
                .then_some(SettingsError::InvalidValue),
            _ => None,
        }
    }

    /// Merges fields that came from another device or the server. A field that may not be here
    /// (a setting that never syncs, a bad name, a value over the limit, an element or rule that
    /// does not match its name, a stamp too far ahead) is left out and named. Values a newer
    /// version added are kept as they are. A remote merge is **always applied**, whatever the
    /// record's size, so devices converge; only a local write is held to the record limit.
    pub fn accept_remote(&mut self, theirs: &Fields, now_millis: u64) -> Accepted {
        let mut accepted = Fields::default();
        let mut rejected = Vec::new();
        for (name, field) in &theirs.0 {
            match Self::refuse(name, &field.value) {
                Some(error) => rejected.push(Rejected {
                    name: name.clone(),
                    error,
                }),
                None => {
                    accepted.0.insert(name.clone(), field.clone());
                }
            }
        }
        let merged = merge_remote(&self.fields, &accepted, now_millis);
        for name in merged.rejected {
            rejected.push(Rejected {
                name,
                error: SettingsError::TooFarAhead,
            });
        }
        self.fields = merged.fields;
        rejected.sort_by(|a, b| a.name.cmp(&b.name));
        Accepted { rejected }
    }
}
