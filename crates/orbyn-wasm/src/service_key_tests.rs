//! The service-key check through the JSON boundary, against a fake transparency log.

use super::*;
use crate::tests::ACCOUNT;
use serde_json::{Value, json};

/// A head as the key service's public API serves it, from `log`'s signed head.
fn served_head(signed: &orbyn_translog::verify::SignedHead) -> Value {
    json!({
        "head": hex(&signed.head.encode()),
        "log_signature": hex(&signed.log_signature),
        "cosignatures": signed.cosignatures.iter().map(|(key, cosignature)| json!({
            "witness_key": hex(key),
            "cosignature": hex(&cosignature.encode()),
        })).collect::<Vec<_>>(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A log holding one certification of `service` for `ACCOUNT`, and every answer the host
/// fetches to check it: the pins, the lookup, the chain's page and the offered certification.
fn service_key_world(service: &orbyn_crypto::P256Keys) -> (Value, Value, [u8; 32]) {
    use ed25519_dalek::Signer;
    use orbyn_translog::testing::{Log, T0};
    use orbyn_translog::{KIND_SERVICE_KEY, certification_fields, service_account_map_key};

    let account = uuid_bytes(ACCOUNT).expect("uuid");
    let statement = orbyn_crypto::service_key_statement(1, &account, &service.public());
    let identity = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let signature = identity
        .sign(&orbyn_crypto::service_key_signed_bytes(&statement))
        .to_bytes();
    let map_key = service_account_map_key(service.public().compressed());

    let mut log = Log::new(3);
    let entry_index = log.append(
        map_key,
        KIND_SERVICE_KEY,
        certification_fields(&statement, &signature).expect("fields"),
        T0 - 10,
    );
    let signed = log.head();
    let mut lookup = served_head(&signed);
    lookup["root"] = json!(hex(&signed.head.service_map_root));
    lookup["proof"] = json!(hex(&log.map_proof(&map_key)));
    let mut page = served_head(&signed);
    page["entries"] = json!(
        log.items(&map_key)
            .iter()
            .map(|item| json!({
                "index": item.index,
                "chain_index": item.chain_index,
                "entry": hex(&item.entry),
                "inclusion_proof": item.inclusion_proof.iter().map(|p| hex(p)).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>()
    );
    let statement_hash = orbyn_crypto::service_key_statement_hash(&statement);

    let pins = log.pins(2);
    let input = json!({
        "pins": {
            "log_keys": pins.log_keys.iter()
                .map(|(version, key)| json!({"version": version, "key": b64(key)})).collect::<Vec<_>>(),
            "witnesses": pins.witnesses.iter().map(|w| b64(w)).collect::<Vec<_>>(),
            "threshold": pins.threshold,
            "identity_keys": [{"version": 1, "key": b64(&identity.verifying_key().to_bytes())}],
        },
        "account_id": ACCOUNT,
        "offered": {
            "account_id": ACCOUNT,
            "identity_version": 1,
            "public_key": b64(service.public().compressed()),
            "statement_hash": b64(&statement_hash),
            "signature": b64(&signature),
            "entry_index": entry_index,
        },
        "answers": {"lookup": lookup.to_string(), "entry_pages": [page.to_string()], "consistency": null},
        "known_key": null,
        "seen": null,
        "now": (orbyn_translog::testing::T0 + 60_000) as f64,
    });
    (input, json!({"size": signed.head.size}), statement_hash)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn the_service_key_check_answers_a_host_through_json() -> Result<()> {
    let service = orbyn_crypto::P256Keys::generate()?;
    let (input, head, hash) = service_key_world(&service);

    // The first check is trust on first use: a key the log agrees with is accepted, and the host
    // stores the key and the head to pass back next time.
    let verdict: Value =
        serde_json::from_str(&crate::service_key::verify_service_key(&input.to_string())?)
            .map_err(|e| error("invalid_json", e))?;
    let verified = &verdict["verified"];
    assert_eq!(
        verified["public_key"],
        json!(b64(service.public().compressed()))
    );
    assert_eq!(verified["statement_hash"], json!(b64(&hash)));
    assert_eq!(verified["entry_index"], input["offered"]["entry_index"]);
    assert_eq!(verified["seen"]["size"], head["size"]);
    assert!(verdict.get("refusal").is_none());

    // The same head again passes, with the key this device already verified.
    let mut again = input.clone();
    again["known_key"] = verified["public_key"].clone();
    again["seen"] = verified["seen"].clone();
    let verdict: Value =
        serde_json::from_str(&crate::service_key::verify_service_key(&again.to_string())?)
            .map_err(|e| error("invalid_json", e))?;
    assert!(verdict.get("verified").is_some());

    // A different key for the account is the takeover the log alone cannot show, and it warns.
    let mut changed = input.clone();
    changed["known_key"] = json!(b64(&[3; 33]));
    let verdict: Value = serde_json::from_str(&crate::service_key::verify_service_key(
        &changed.to_string(),
    )?)
    .map_err(|e| error("invalid_json", e))?;
    assert_eq!(verdict["refusal"]["code"], json!("key_changed"));
    assert_eq!(verdict["refusal"]["takeover"], json!(true));
    assert!(verdict.get("verified").is_none());

    // A root that is not 32 bytes of hex is the host's mistake, not a verdict.
    let mut bad = input;
    bad["seen"] = json!({"size": 1, "log_root": "zz", "service_map_root": "00", "identity_map_root": "00", "witnessed_ms": 0});
    assert_eq!(
        crate::service_key::verify_service_key(&bad.to_string()).map_err(|e| e.code),
        Err("invalid_input")
    );
    Ok(())
}
