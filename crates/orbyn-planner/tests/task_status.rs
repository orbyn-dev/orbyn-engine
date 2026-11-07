//! Runs the shared task status vectors (`tests/vectors/task-status.json`), which the planner's web
//! tests run too, so every client reads and merges status the same way.

use jiff::Timestamp;
use orbyn_planner::{Item, Lane, Status};
use orbyn_sync::{Fields, Stamp, merge};
use serde_json::{Value, json};

fn vectors() -> Value {
    let text = include_str!("vectors/task-status.json");
    serde_json::from_str(text).expect("the vectors are JSON")
}

fn stamp(millis: u64, device: u64) -> Stamp {
    Stamp {
        millis,
        counter: 0,
        device,
    }
}

/// The three fields every record needs, stamped at 1, and then `set` on top.
fn base_fields(set: &Value) -> Fields {
    let mut fields = Fields::default();
    for (name, value) in [
        ("kind", json!("task")),
        ("title", json!("Task")),
        ("list_id", json!("home")),
    ] {
        fields.set(name, value, stamp(1, 0));
    }
    for (name, value) in set.as_object().expect("an object") {
        fields.set(name, value.clone(), stamp(1, 0));
    }
    fields
}

fn lane_of(name: &str) -> Lane {
    serde_json::from_value(json!(name)).expect("a lane")
}

fn item(status: &str, done: bool) -> Item {
    let mut set = json!({ "status": status });
    if done {
        set["done_at"] = json!("2026-11-08T09:00:00Z");
    }
    Item::from_fields("t1", &base_fields(&set)).expect("an item")
}

fn now() -> Timestamp {
    "2026-11-09T10:00:00Z".parse().expect("time")
}

#[test]
fn reading_records() {
    for case in vectors()["reading"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let item = Item::from_fields("t1", &base_fields(&case["fields"])).expect(name);
        assert_eq!(item.status.as_str(), case["status"], "{name}: status");
        assert_eq!(
            item.lane(),
            lane_of(case["lane"].as_str().expect("lane")),
            "{name}: lane"
        );
        // Reading and writing back loses nothing: an unknown status is kept as it was.
        let again = Item::from_fields("t1", &item.to_fields(stamp(2, 1))).expect(name);
        assert_eq!(again, item, "{name}: round trip");
    }
}

#[test]
fn a_record_with_no_status_writes_nothing_until_it_changes() {
    let old = Item::from_fields("t1", &base_fields(&json!({}))).expect("item");
    assert_eq!(old.status, Status::Todo);
    // An edit that does not touch the status does not write one.
    let mut edited = old.clone();
    edited.title = "Renamed".into();
    let changed = edited.changed_fields(&old, stamp(5, 1));
    assert!(changed.get("status").is_none(), "{changed:?}");
    // Changing it writes only `status`.
    let mut moved = old.clone();
    moved.status = Status::Blocked;
    let changed = moved.changed_fields(&old, stamp(5, 1));
    assert_eq!(changed.0.keys().collect::<Vec<_>>(), ["status"]);
    assert_eq!(changed.get("status"), Some(&json!("blocked")));
}

#[test]
fn lane_moves() {
    for case in vectors()["moves"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let from = &case["from"];
        let before = item(
            from["status"].as_str().expect("status"),
            from["done"] == true,
        );
        let mut moved = before.clone();
        moved.move_to(lane_of(case["to"].as_str().expect("to")), now());
        assert_eq!(
            moved.status.as_str(),
            case["expect"]["status"],
            "{name}: status"
        );
        assert_eq!(
            moved.done_at.is_some(),
            case["expect"]["done"] == true,
            "{name}: done"
        );
        // What a move writes: a move between open lanes writes only `status`; to Done only `done_at`.
        let changed = moved.changed_fields(&before, stamp(9, 1));
        let written: Vec<&str> = changed.0.keys().map(String::as_str).collect();
        let to = case["to"].as_str().expect("to");
        if before.lane() == moved.lane() {
            assert!(written.is_empty(), "{name}: {written:?}");
        } else if to == "done" {
            assert_eq!(written, ["done_at"], "{name}");
        } else if before.done_at.is_some() {
            assert!(
                written.iter().all(|w| ["done_at", "status"].contains(w)),
                "{name}: {written:?}"
            );
        } else {
            assert_eq!(written, ["status"], "{name}");
        }
    }
}

#[test]
fn undo_restores_status_done_and_done_at_exactly() {
    for case in vectors()["undo"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let b = &case["before"];
        let before = item(b["status"].as_str().expect("status"), b["done"] == true);
        let mut moved = before.clone();
        moved.move_to(lane_of(case["moved_to"].as_str().expect("to")), now());
        // Undo is one write of the three values the move may have changed.
        let mut undone = moved.clone();
        undone.status = before.status.clone();
        undone.done_at = before.done_at;
        assert_eq!(undone, before, "{name}");
        let a = &case["after_undo"];
        assert_eq!(undone.status.as_str(), a["status"], "{name}");
        assert_eq!(undone.done_at.is_some(), a["done"] == true, "{name}");
        // And what it writes on top of the moved record puts the old values back after a merge.
        let mut merged = moved.to_fields(stamp(10, 1));
        merged = merge(&merged, &undone.changed_fields(&moved, stamp(11, 1)));
        assert_eq!(
            Item::from_fields("t1", &merged).expect(name),
            before,
            "{name}: merged"
        );
    }
}

/// Merges each write in as one device's edit, in the order given.
fn apply(fields: &mut Fields, writes: &[Value]) {
    for write in writes {
        let at = stamp(
            write["millis"].as_u64().expect("millis"),
            write["device"].as_u64().expect("device"),
        );
        let mut one = Fields::default();
        for (name, value) in write["set"].as_object().expect("set") {
            one.set(name, value.clone(), at);
        }
        *fields = merge(fields, &one);
    }
}

fn check_state(name: &str, item: &Item, expect: &Value) {
    assert_eq!(item.status.as_str(), expect["status"], "{name}: status");
    assert_eq!(
        item.done_at.is_some(),
        expect["done"] == true,
        "{name}: done"
    );
    assert_eq!(
        item.lane(),
        lane_of(expect["lane"].as_str().expect("lane")),
        "{name}: lane"
    );
}

#[test]
fn merges() {
    for case in vectors()["merge"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        // In the order given and in the reverse order: a merge does not depend on arrival.
        for reverse in [false, true] {
            let mut fields = base_fields(&case["base"]);
            let mut writes = case["writes"].as_array().expect("writes").clone();
            if reverse {
                writes.reverse();
            }
            apply(&mut fields, &writes);
            let item = Item::from_fields("t1", &fields).expect(name);
            check_state(name, &item, &case["expect"]);
            if let Some(then) = case.get("then") {
                apply(&mut fields, then.as_array().expect("then"));
                let item = Item::from_fields("t1", &fields).expect(name);
                check_state(name, &item, &case["expect_after"]);
            }
        }
    }
}

#[test]
fn the_repeat_reset() {
    for case in vectors()["repeat"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let mut task = item(case["before"]["status"].as_str().expect("status"), false);
        task.reset_status_for_next_occurrence();
        assert_eq!(task.status.as_str(), case["expect"]["status"], "{name}");
        assert_eq!(
            task.done_at.is_some(),
            case["expect"]["done"] == true,
            "{name}"
        );
    }
}

#[test]
fn the_ics_mapping() {
    for case in vectors()["ics"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let task = item(
            case["status"].as_str().expect("status"),
            case["done"] == true,
        );
        let (status, extra) = task.ics_status();
        assert_eq!(status, case["STATUS"], "{name}");
        assert_eq!(
            extra.map(Value::from).unwrap_or(Value::Null),
            case["X-ORBYN-STATUS"],
            "{name}"
        );
    }
}

#[test]
fn the_json_export_has_the_status() {
    for case in vectors()["json_export"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let task = item(
            case["status"].as_str().expect("status"),
            case["done"] == true,
        );
        let exported = serde_json::to_value(&task).expect("json");
        assert_eq!(exported["status"], case["exports"]["status"], "{name}");
        let back: Item = serde_json::from_value(exported).expect("read back");
        assert_eq!(back, task, "{name}");
        // An older export with no status field reads as todo.
        let mut old = serde_json::to_value(&task).expect("json");
        old.as_object_mut().expect("object").remove("status");
        let old: Item = serde_json::from_value(old).expect("old export");
        assert_eq!(old.status, Status::Todo, "{name}");
    }
}
