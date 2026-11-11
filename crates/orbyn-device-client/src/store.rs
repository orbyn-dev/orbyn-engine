//! Where a device keeps its secrets. Only what must outlive a run: the device keys, the account
//! and device ids with the email, the session token and the vault key. The zone-key cache is not
//! here: the host keeps it in its own snapshot, sealed under the vault key.

use crate::error::StoreError;
use orbyn_crypto::DeviceKeys;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// A session as the server gave it.
#[derive(Clone)]
pub struct StoredSession {
    /// The bearer token. Never logged.
    pub token: Zeroizing<String>,
    /// RFC 3339, as the server sent it.
    pub expires_at: String,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredSession(..)")
    }
}

/// Everything a device persists.
#[derive(Clone)]
pub struct StoredIdentity {
    /// The device keys: Ed25519 then X25519 secrets ([`DeviceKeys::to_bytes`]).
    pub device_keys: Zeroizing<[u8; 64]>,
    pub account_id: String,
    pub device_id: String,
    /// The normalised email: an identifier, kept so a re-login needs only the password.
    pub email: String,
    /// `None` after a sign-out that kept the device.
    pub session: Option<StoredSession>,
    /// 32 random bytes made on this device. The host seals its snapshot under it. It never leaves
    /// the device and is not derived from the password.
    pub vault_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoredIdentity(..)")
    }
}

impl StoredIdentity {
    /// The device keys as a key object.
    pub fn keys(&self) -> Result<DeviceKeys, crate::DeviceError> {
        DeviceKeys::from_bytes(self.device_keys.as_slice()).map_err(|_| crate::DeviceError::Crypto)
    }
}

/// The device's secret storage: the OS keychain in the app. Calls are synchronous and short.
pub trait KeyStore: Send + Sync {
    /// The saved identity, if any.
    fn load(&self) -> Result<Option<StoredIdentity>, StoreError>;
    /// Replaces the saved identity, all or nothing.
    fn save(&self, identity: &StoredIdentity) -> Result<(), StoreError>;
    /// Forgets everything.
    fn clear(&self) -> Result<(), StoreError>;
}

/// A store in memory, for tests and for a run that must keep nothing.
#[derive(Default)]
pub struct MemoryStore {
    slot: Mutex<Option<StoredIdentity>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredIdentity>, StoreError> {
        Ok(self.slot.lock().map_err(|_| StoreError)?.clone())
    }

    fn save(&self, identity: &StoredIdentity) -> Result<(), StoreError> {
        *self.slot.lock().map_err(|_| StoreError)? = Some(identity.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), StoreError> {
        *self.slot.lock().map_err(|_| StoreError)? = None;
        Ok(())
    }
}
