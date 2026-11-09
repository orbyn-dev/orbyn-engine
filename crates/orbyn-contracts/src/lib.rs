//! Wire types for every API and event of orbyn-engine.
//!
//! This crate is the only source of wire types. `cargo test -p orbyn-contracts`
//! regenerates the TypeScript in `bindings/`, which clients copy; commit the
//! bindings in the same change as the types.

mod auth;
mod devices;
mod feeds;
mod health;
mod keys;
mod protection;
mod records;
mod sync;
mod zones;

pub use auth::*;
pub use devices::*;
pub use feeds::*;
pub use health::*;
pub use keys::*;
pub use protection::*;
pub use records::*;
pub use sync::*;
pub use zones::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_uses_snake_case_states() {
        let health = Health {
            status: ServiceState::Ok,
            version: "0.1.0".into(),
            database: ServiceState::Unavailable,
        };
        let json = serde_json::to_string(&health).expect("serialize");
        assert_eq!(
            json,
            r#"{"status":"ok","version":"0.1.0","database":"unavailable"}"#
        );
    }

    #[test]
    fn changes_and_sync_messages_are_tagged() {
        let delete = RecordChange::Delete {
            record_id: "a".into(),
            expected_version: 3,
            proof: None,
        };
        assert_eq!(
            serde_json::to_string(&delete).expect("serialize"),
            r#"{"op":"delete","record_id":"a","expected_version":3,"proof":null}"#
        );
        let save: RecordChange = serde_json::from_str(
            r#"{"op":"save","record_id":"a","record_type":"task","expected_version":null,"ciphertext":"AA","wrapped_key":""}"#,
        )
        .expect("deserialize");
        assert!(matches!(
            save,
            RecordChange::Save {
                expected_version: None,
                ..
            }
        ));
        assert_eq!(
            serde_json::to_string(&SyncServerMessage::Resync).expect("serialize"),
            r#"{"type":"resync"}"#
        );
        let auth: SyncClientMessage =
            serde_json::from_str(r#"{"type":"auth","token":"t"}"#).expect("deserialize");
        assert_eq!(auth, SyncClientMessage::Auth { token: "t".into() });
    }

    #[test]
    fn device_states_and_platforms_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&(DeviceState::Pending, DevicePlatform::Macos))
                .expect("serialize"),
            r#"["pending","macos"]"#
        );
    }
}
