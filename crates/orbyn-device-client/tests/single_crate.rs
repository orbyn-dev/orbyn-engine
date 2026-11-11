//! The app may not name `orbyn-contracts` (rule D6): every type that this crate's public API
//! exposes must be nameable from this crate alone. This file imports from `orbyn_device_client`
//! and nothing else, and a second test checks that it stays that way.

use orbyn_device_client::{
    Applied, ClientConfig, ClientError, Device, DeviceApp, DeviceKeys, DeviceList, DevicePlatform,
    DevicePublic, DeviceRemoval, DeviceState, Engine, Fields, KeyStore, Local, MemoryStore,
    Password, Peer, PendingApproval, Quarantined, RefusedEnvelope, RejectedFields, Snapshot, Stamp,
    StoredIdentity, SyncReport, Trashed, Zeroizing, ZoneReport,
};

/// A host's `ClientConfig` is written with the re-exported platform and app types.
fn config() -> ClientConfig {
    ClientConfig {
        device_name: "Laptop".to_owned(),
        platform: DevicePlatform::Linux,
        app: Some(DeviceApp::Engineering),
    }
}

/// Every type is usable in a signature, which is how a host holds them.
#[allow(dead_code)]
type Held<'a> = (
    Option<&'a Peer>,
    Option<&'a Local>,
    Option<&'a Quarantined>,
    Option<&'a Trashed>,
    Option<&'a RejectedFields>,
    Option<&'a RefusedEnvelope>,
    Option<&'a ClientError>,
    Option<&'a PendingApproval>,
    Option<&'a DeviceRemoval>,
    Option<&'a DevicePublic>,
);

#[test]
fn a_host_names_the_device_types_from_this_crate_alone() {
    let config = config();
    assert_eq!(config.platform, DevicePlatform::Linux);
    assert_eq!(config.app, Some(DeviceApp::Engineering));
    assert_eq!(DeviceApp::Planner.as_str(), "planner");
    assert_eq!(DevicePlatform::Macos.as_str(), "macos");

    // A device list is read with the re-exported types.
    let list = DeviceList {
        devices: Vec::<Device>::new(),
        removals: Vec::<DeviceRemoval>::new(),
    };
    assert!(list.devices.is_empty());
    assert_ne!(DeviceState::Pending, DeviceState::Trusted);
}

#[test]
fn a_host_drives_the_engine_and_a_key_store_with_the_re_exported_types() {
    let keys = DeviceKeys::generate().expect("keys");
    let mut engine = Engine::new(
        keys,
        "0a0a0a0a-0000-4000-8000-000000000001",
        "0000000a-0000-4000-8000-00000000000a",
    )
    .expect("engine");
    let stamp: Stamp = engine.tick(1_700_000_000_000);
    let mut fields = Fields::default();
    fields.set("name", serde_json::json!("x"), stamp);
    assert!(engine.zones().next().is_none());
    let snapshot: Snapshot = engine.snapshot();
    assert_eq!(snapshot.device_id, "0000000a-0000-4000-8000-00000000000a");
    assert_eq!(Applied::default().changed.len(), 0);
    let report = SyncReport {
        zones: vec![ZoneReport::default()],
        ..SyncReport::default()
    };
    assert_eq!(report.zones.len(), 1);

    // A host's key store holds the identity with the re-exported wiping type.
    let store = MemoryStore::new();
    store
        .save(&StoredIdentity {
            device_keys: DeviceKeys::generate().expect("keys").to_bytes(),
            account_id: "a".into(),
            device_id: "d".into(),
            email: "e@example.com".into(),
            session: None,
            vault_key: Zeroizing::new([1u8; 32]),
        })
        .expect("save");
    assert!(store.load().expect("load").is_some());
}

#[test]
fn a_host_builds_a_password_from_this_crate_alone() {
    let password = Password::new("hunter2 but longer");
    assert!(!format!("{password:?}").contains("hunter2"));
}

#[test]
fn this_file_never_names_another_engine_crate() {
    let source = include_str!("single_crate.rs");
    // Built from pieces so this check does not match itself.
    for name in [
        "contracts",
        "crypto",
        "sync",
        "auth_client",
        "zeroize",
        "planner",
    ] {
        let needle = format!("orbyn_{name}");
        let uses = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.contains("let needle"))
            .filter(|l| l.contains(&needle) && !l.contains("for name in"))
            .count();
        assert_eq!(uses, 0, "{needle} is named in this file");
    }
    let zeroize_use = source
        .lines()
        .any(|l| l.trim_start().starts_with("use zeroize"));
    assert!(!zeroize_use);
}
