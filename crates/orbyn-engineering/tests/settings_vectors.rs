//! Runs the shared settings vectors (`tests/vectors/settings.json`), which the app can run too, so
//! every client derives names, reads defaults and merges the same way.

use orbyn_engineering::keys::{self, Class};
use orbyn_engineering::{Rule, Settings, SettingsError, check_name};
use orbyn_sync::{Fields, Stamp};
use serde_json::{Value, json};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/settings.json")).expect("the vectors are JSON")
}

fn error_name(error: SettingsError) -> &'static str {
    match error {
        SettingsError::InvalidKey => "invalid_key",
        SettingsError::NotSynced => "not_synced",
        SettingsError::TooLarge => "too_large",
        SettingsError::UnknownKey => "unknown_key",
        SettingsError::InvalidValue => "invalid_value",
        SettingsError::TooFarAhead => "too_far_ahead",
    }
}

/// `{repeat: {text, count}}` and `{repeat_list: {text, count}}` become the long values they stand for.
fn expand(value: &Value) -> Value {
    if let Some(spec) = value.get("repeat") {
        let text = spec["text"].as_str().expect("text");
        return json!(text.repeat(spec["count"].as_u64().expect("count") as usize));
    }
    if let Some(spec) = value.get("repeat_list") {
        let text = spec["text"].as_str().expect("text");
        let count = spec["count"].as_u64().expect("count") as usize;
        return json!(vec![text; count]);
    }
    match value {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), expand(v))).collect())
        }
        other => other.clone(),
    }
}

fn stamp(op: &Value, device: u64) -> Stamp {
    Stamp {
        millis: op["t"].as_u64().expect("t"),
        counter: 0,
        device: op["as"].as_u64().unwrap_or(device),
    }
}

fn rule(value: &Value) -> Rule {
    serde_json::from_value(value.clone()).expect("a rule")
}

fn apply(settings: &mut Settings, op: &Value, device: u64) {
    let before = settings.fields().clone();
    let at = stamp(op, device);
    let list = |op: &Value, name: &str| -> (String, String) {
        let pair = op[name].as_array().expect(name);
        (
            pair[0].as_str().expect("list").to_owned(),
            pair[1].as_str().expect("id").to_owned(),
        )
    };
    let result = if let Some(pair) = op.get("set") {
        settings.set(pair[0].as_str().expect("key"), expand(&pair[1]), at)
    } else if op.get("add").is_some() {
        let (name, id) = list(op, "add");
        settings.add(&name, &id, at)
    } else if op.get("remove").is_some() {
        let (name, id) = list(op, "remove");
        settings.remove(&name, &id, at)
    } else if let Some(rule_value) = op.get("bind") {
        settings.bind(&rule(rule_value), at)
    } else if let Some(target) = op.get("unbind") {
        settings.unbind(
            target["key"].as_str().expect("key"),
            target["when"].as_str(),
            at,
        )
    } else if let Some(pair) = op.get("fill") {
        let (name, count) = (
            pair[0].as_str().expect("list"),
            pair[1].as_u64().expect("n"),
        );
        let width = pair.get(2).and_then(Value::as_u64).unwrap_or(0) as usize;
        let prefix = pair.get(3).and_then(Value::as_str).unwrap_or("member-");
        (0..count).try_for_each(|i| {
            let id = format!("{prefix}{i:03}");
            settings.add(name, &format!("{id:x<width$}"), at)
        })
    } else if let Some(pair) = op.get("churn") {
        // Adds and removes `n` distinct ids: each add at `t`, its removal a millisecond later.
        let (name, count) = (
            pair[0].as_str().expect("list"),
            pair[1].as_u64().expect("n"),
        );
        let later = Stamp {
            millis: at.millis + 1,
            ..at
        };
        (0..count).try_for_each(|i| {
            let id = format!("churn-{i:04}");
            settings.add(name, &id, at)?;
            settings.remove(name, &id, later)
        })
    } else {
        panic!("an op this runner does not know: {op}");
    };
    match op.get("error") {
        Some(expected) => {
            assert_eq!(
                result.map_err(error_name),
                Err(expected.as_str().expect("name")),
                "{op}"
            );
            // A single refused write changes nothing (a fill or a churn is many writes, and the
            // ones before the refusal stay).
            if op.get("fill").is_none() && op.get("churn").is_none() {
                assert_eq!(
                    settings.fields(),
                    &before,
                    "a refused write changes nothing: {op}"
                );
            }
        }
        None => assert_eq!(result, Ok(()), "{op}"),
    }
}

fn device(ops: Option<&Value>, injected: Option<&Value>, id: u64) -> Settings {
    let mut settings = Settings::default();
    for op in ops.and_then(Value::as_array).into_iter().flatten() {
        apply(&mut settings, op, id);
    }
    let mut fields = settings.into_fields();
    for (name, field) in injected.and_then(Value::as_object).into_iter().flatten() {
        let field: orbyn_sync::Field = serde_json::from_value(field.clone()).expect("a field");
        fields.0.insert(name.clone(), field);
    }
    Settings::from_fields(fields)
}

#[test]
fn field_names_are_derived_the_same_way_everywhere() {
    for case in vectors()["derivation"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let field = if let Some(list) = case["list"].as_str() {
            keys::element_field(list, case["id"].as_str().expect("id"))
        } else {
            keys::keybinding_field(case["key"].as_str().expect("key"), case["when"].as_str())
        };
        assert_eq!(field, case["field"], "{name}");
        assert!(check_name(&field).is_ok(), "{name}: {field}");
    }
}

#[test]
fn keys_are_checked_by_the_key_rule_and_the_never_synced_list() {
    for case in vectors()["keys"].as_array().expect("cases") {
        let key = case["key"].as_str().expect("key");
        match (case.get("error"), case.get("ok").and_then(Value::as_str)) {
            (Some(error), _) => assert_eq!(
                check_name(key).map(|_| ()).map_err(error_name),
                Err(error.as_str().expect("e")),
                "{key:?}"
            ),
            (None, Some(kind)) => {
                let class = check_name(key).unwrap_or_else(|e| panic!("{key}: {e}"));
                let got = match class {
                    Class::Plain(Some(_)) => "plain",
                    Class::Plain(None) => "plain_unknown",
                    Class::Element(_) => "element",
                    Class::Keybinding => "keybinding",
                };
                assert_eq!(got, kind, "{key}");
            }
            _ => panic!("a case needs `ok` or `error`"),
        }
    }
}

#[test]
fn defaults_are_what_nobody_set_reads_as() {
    let settings = Settings::default();
    let defaults = vectors()["defaults"].clone();
    for (key, want) in defaults.as_object().expect("defaults") {
        assert_eq!(settings.get(key).expect(key), *want, "{key}");
    }
    assert_eq!(
        defaults.as_object().expect("defaults").len(),
        keys::SPECS.len(),
        "every plain field has a default"
    );
    assert!(settings.fields().0.is_empty(), "reading writes nothing");
    for (key, options) in vectors()["enums"].as_object().expect("enums") {
        let spec = keys::spec(key).expect(key);
        let listed: Vec<&str> = options
            .as_array()
            .expect("list")
            .iter()
            .filter_map(Value::as_str)
            .filter(|o| !o.starts_with('<'))
            .collect();
        match spec.kind {
            keys::Kind::Enum(have) | keys::Kind::EnumOrThemeId(have) => {
                assert_eq!(have, listed.as_slice(), "{key}")
            }
            other => panic!("{key} is {other:?}"),
        }
    }
}

fn check_expect(name: &str, settings: &Settings, expect: &Value) {
    for (key, want) in expect["values"].as_object().into_iter().flatten() {
        assert_eq!(settings.get(key).expect(key), *want, "{name}: {key}");
    }
    for (list, want) in expect["members"].as_object().into_iter().flatten() {
        let want: Vec<String> = serde_json::from_value(want.clone()).expect("ids");
        assert_eq!(settings.members(list).expect(list), want, "{name}: {list}");
    }
    for (list, range) in expect["members_between"].as_object().into_iter().flatten() {
        let n = settings.members(list).expect(list).len() as u64;
        let (low, high) = (
            range[0].as_u64().expect("low"),
            range[1].as_u64().expect("high"),
        );
        assert!((low..=high).contains(&n), "{name}: {list} has {n}");
    }
    for (list, count) in expect["members_count"].as_object().into_iter().flatten() {
        assert_eq!(
            settings.members(list).expect(list).len() as u64,
            count.as_u64().expect("n"),
            "{name}: {list}"
        );
    }
    for field in expect["has_field"].as_array().into_iter().flatten() {
        let field = field.as_str().expect("name");
        assert!(
            settings.fields().0.contains_key(field),
            "{name}: has {field}"
        );
    }
    for field in expect["no_field"].as_array().into_iter().flatten() {
        let field = field.as_str().expect("name");
        assert!(
            !settings.fields().0.contains_key(field),
            "{name}: no {field}"
        );
    }
    if let Some(over) = expect["record_bytes_over"].as_u64() {
        let bytes = serde_json::to_vec(settings.fields()).expect("json").len() as u64;
        assert!(bytes > over, "{name}: the record is {bytes} bytes");
    }
    if let Some(want) = expect.get("keybindings") {
        let want: Vec<Rule> = serde_json::from_value(want.clone()).expect("rules");
        assert_eq!(settings.keybindings(), want, "{name}: keybindings");
    }
    for (field, want) in expect["raw"].as_object().into_iter().flatten() {
        assert_eq!(settings.raw(field), Some(want), "{name}: raw {field}");
    }
    if let Some(want) = expect.get("unknown") {
        let want: Vec<String> = serde_json::from_value(want.clone()).expect("names");
        assert_eq!(settings.unknown(), want, "{name}: unknown");
    }
}

#[test]
fn scenarios() {
    let all = vectors();
    let now = all["now_ms"].as_u64().expect("now");
    for case in all["scenarios"].as_array().expect("scenarios") {
        let name = case["name"].as_str().expect("name");
        let mut devices = [("A", 1u64), ("B", 2u64)].map(|(label, id)| {
            (
                label,
                device(case["devices"].get(label), case["inject"].get(label), id),
            )
        });
        let merge = case["merge"].as_array().expect("merge");
        if let [x, y] = merge.as_slice() {
            let index = |v: &Value| usize::from(v.as_str() == Some("B"));
            let (x, y) = (index(x), index(y));
            let theirs = devices[y].1.fields().clone();
            let accepted = devices[x].1.accept_remote(&theirs, now);
            if let Some(want) = case["expect"].get("rejected") {
                let got: Vec<Value> = accepted
                    .rejected
                    .iter()
                    .map(|r| json!({ "name": r.name, "error": error_name(r.error) }))
                    .collect();
                assert_eq!(Value::Array(got), *want, "{name}: rejected");
            } else {
                assert!(
                    accepted.rejected.is_empty(),
                    "{name}: {:?}",
                    accepted.rejected
                );
            }
            let ours: Fields = devices[x].1.fields().clone();
            devices[y].1.accept_remote(&ours, now);
            if accepted.rejected.is_empty() {
                assert_eq!(
                    devices[x].1.fields(),
                    devices[y].1.fields(),
                    "{name}: both ends equal"
                );
            }
            // Merging the same fields again changes nothing.
            let settled = devices[x].1.fields().clone();
            devices[x].1.accept_remote(&settled, now);
            assert_eq!(devices[x].1.fields(), &settled, "{name}: idempotent");
            check_expect(name, &devices[x].1, &case["expect"]);
            if accepted.rejected.is_empty() {
                check_expect(name, &devices[y].1, &case["expect"]);
            }
            // Local writes after the merge, on the first device: the record cap holds for them.
            for op in case["after"].as_array().into_iter().flatten() {
                apply(&mut devices[x].1, op, x as u64 + 1);
            }
        } else {
            check_expect(name, &devices[0].1, &case["expect"]);
        }
    }
}

#[test]
fn orbyn_syncs_own_field_names_can_never_be_settings() {
    // `_deleted` makes `Fields::is_deleted` read the record as deleted; it must stay refused even
    // if orbyn-sync renames it.
    assert_eq!(
        check_name(orbyn_sync::DELETED).map(|_| ()),
        Err(SettingsError::InvalidKey)
    );
}
