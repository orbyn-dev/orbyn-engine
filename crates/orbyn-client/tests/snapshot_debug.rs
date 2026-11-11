//! A snapshot holds zone keys and records. Printing it with `{:?}` or `{:#?}` must never show
//! either, in any encoding (the app's threat model, control 4).

use base64::Engine as _;
use orbyn_client::{DeviceKeys, Engine, Fields, Snapshot};
use serde_json::json;

const ZONE: &str = "inbox";
const SECRET_NOTE: &str = "a private note that must not be printed";

/// Every encoding a key could be printed in.
fn encodings(key: &[u8]) -> Vec<String> {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let upper = hex.to_uppercase();
    let std = base64::engine::general_purpose::STANDARD.encode(key);
    let std_nopad = base64::engine::general_purpose::STANDARD_NO_PAD.encode(key);
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
    let url_pad = base64::engine::general_purpose::URL_SAFE.encode(key);
    let decimals: Vec<String> = key.iter().map(u8::to_string).collect();
    let array = format!("[{}]", decimals.join(", "));
    let pretty = format!("[\n    {},\n]", decimals.join(",\n    "));
    let compact = decimals.join(",");
    vec![
        hex, upper, std, std_nopad, url, url_pad, array, pretty, compact,
    ]
}

fn snapshot_with_a_key_and_a_record() -> (Snapshot, Vec<u8>) {
    let mut engine = Engine::new(
        DeviceKeys::generate().expect("keys"),
        "0a0a0a0a-0000-4000-8000-000000000001",
        "0000000a-0000-4000-8000-00000000000a",
    )
    .expect("engine");
    let key_id = engine.create_zone_key(ZONE).expect("zone key");
    let stamp = engine.tick(1_700_000_000_000);
    let mut fields = Fields::default();
    fields.set("note", json!(SECRET_NOTE), stamp);
    engine
        .stage(ZONE, "person_settings", "person", &fields)
        .expect("stage");
    let snapshot = engine.snapshot();
    // The key as the snapshot stores it (base64url), decoded to its bytes.
    let stored = &snapshot.zones[ZONE].keys[&key_id];
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(stored)
        .expect("base64url");
    assert_eq!(bytes.len(), 32);
    (snapshot, bytes)
}

#[test]
fn debug_of_a_snapshot_never_shows_a_zone_key_or_a_record() {
    let (snapshot, key) = snapshot_with_a_key_and_a_record();
    let zone = &snapshot.zones[ZONE];
    let printed = [
        format!("{snapshot:?}"),
        format!("{snapshot:#?}"),
        format!("{:?}", Some(&snapshot)),
        format!("{:#?}", Some(snapshot.clone())),
        format!("{zone:?}"),
        format!("{zone:#?}"),
        format!("{:?}", snapshot.zones),
        format!("{:#?}", snapshot.zones),
    ];
    for text in &printed {
        for encoding in encodings(&key) {
            assert!(
                !text.contains(&encoding),
                "a key shows as {encoding}: {text}"
            );
        }
        assert!(!text.contains(SECRET_NOTE), "a record shows: {text}");
    }
    // It still says whose snapshot it is and how big.
    let text = format!("{snapshot:?}");
    assert!(
        text.contains("0a0a0a0a-0000-4000-8000-000000000001"),
        "{text}"
    );
    assert!(
        text.contains("0000000a-0000-4000-8000-00000000000a"),
        "{text}"
    );
    assert!(text.contains("zones: 1"), "{text}");
}

#[test]
fn the_check_finds_a_key_when_one_is_printed() {
    // A derived Debug of the stored map would print the key: the encodings above catch it.
    let (snapshot, key) = snapshot_with_a_key_and_a_record();
    let leaked = format!("{:?}", snapshot.zones[ZONE].keys);
    assert!(
        encodings(&key).iter().any(|e| leaked.contains(e)),
        "the encodings must match what a derive would print: {leaked}"
    );
}
