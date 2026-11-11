//! The engine's public signatures name types of other Engine crates. A host that depends on
//! `orbyn-client` alone (the app may not name `orbyn-contracts`, rule D6) names them from here.

use orbyn_client::{
    ApprovalNonce, ConfirmApproval, CreateApproval, DeleteZone, Device, DeviceApp, DeviceKeys,
    DeviceList, DevicePlatform, DevicePublic, Engine, Fields, KeyEnvelope, KeyRotation,
    NewKeyEnvelope, PendingApproval, ProtectionChain, ProtectionLevel, ProtectionLink, Record,
    RecordChanged, RemoveDevice, SetProtection, Stamp, UploadChanges, UploadResult, ZoneChanges,
    ZoneList,
};

/// Each wire type the engine's methods take or return is nameable here: this compiles only if the
/// signature below, written with the re-exported names, matches the engine's own.
#[allow(dead_code, clippy::type_complexity)]
fn signatures(engine: &mut Engine, device: &Device, list: &DeviceList) {
    let _: fn(&Engine, &ZoneList) -> _ = Engine::check_zones;
    let _: fn(&mut Engine, &str) -> Result<Option<UploadChanges>, _> = Engine::build_upload;
    let _: fn(&mut Engine, &str, &UploadResult) -> Result<(), _> = Engine::upload_succeeded;
    let _: fn(&Engine, &Device) -> Result<RemoveDevice, _> = Engine::sign_removal;
    let _: fn(&Engine, &str) -> Result<DeleteZone, _> = Engine::delete_zone_proof;
    let _ = (engine, device, list);
}

#[allow(dead_code)]
type Named = (
    ApprovalNonce,
    ConfirmApproval,
    CreateApproval,
    DeviceApp,
    DevicePlatform,
    KeyEnvelope,
    KeyRotation,
    NewKeyEnvelope,
    PendingApproval,
    ProtectionChain,
    ProtectionLevel,
    ProtectionLink,
    Record,
    RecordChanged,
    SetProtection,
    ZoneChanges,
);

#[test]
fn the_re_exports_are_the_contract_and_crypto_types_themselves() {
    let keys = DeviceKeys::generate().expect("keys");
    let public: DevicePublic = keys.public();
    let engine = Engine::new(
        keys,
        "0a0a0a0a-0000-4000-8000-000000000001",
        "0000000a-0000-4000-8000-00000000000a",
    )
    .expect("engine");
    assert_eq!(engine.device_keys().public(), public);
    let mut engine = engine;
    let stamp: Stamp = engine.tick(1_700_000_000_000);
    let mut fields = Fields::default();
    fields.set("a", serde_json::json!(1), stamp);
    assert_eq!(DeviceApp::Engineering.as_str(), "engineering");
    assert_eq!(DevicePlatform::Windows.as_str(), "windows");
}
