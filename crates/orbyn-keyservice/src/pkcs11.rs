//! The PKCS#11 implementation of [`Hsm`](crate::Hsm), through `cryptoki`: SoftHSM for development,
//! CI and self-hosting, or a cloud HSM's PKCS#11 module in production.
//!
//! - The **KEK** is a non-extractable, sensitive AES-256 token object (`orbyn-kek-v1`) that only
//!   wraps and unwraps.
//! - An **identity** is an Ed25519 key pair (`orbyn-identity-v<N>`), the private half a
//!   non-extractable, sensitive token object that only signs.
//! - An **account key** is a P-256 pair made as session objects, wrapped under the KEK with
//!   `CKM_AES_KEY_WRAP_PAD` (RFC 5649, the AES key wrap with padding the design calls KWP) and
//!   destroyed before the call returns. To use one it is unwrapped into a session object (not on the
//!   token, non-extractable) and used with `CKM_ECDH1_DERIVE` and `CKD_NULL`, the peer given as the
//!   uncompressed point of a validated [`P256Point`](orbyn_crypto::P256Point); the derived value is
//!   read and destroyed.
//! - SoftHSM has no `CKM_HKDF_DERIVE`, so HKDF runs in the key service, in memory.
//!
//! Every key template sets every usage flag, true only for what the key is for.
//!
//! **Accepted limits.** The derived secret is read with `C_GetAttributeValue` through `cryptoki`,
//! which hands back a `Vec`; it is moved into a `Zeroizing` buffer at once, but the crate does not
//! expose the raw function list, so the read cannot go straight into a buffer of ours, and this
//! crate forbids `unsafe`. Copies `cryptoki` makes inside the call are not under our control; the
//! secret exists only for the one derive. **Required for production, not done on SoftHSM:** the KEK
//! should be marked `CKA_TRUSTED` by the Security Officer at `init`, and account keys created with
//! `CKA_WRAP_WITH_TRUSTED`, so that only the trusted KEK can wrap them. SoftHSM cannot do this
//! cleanly: the Security Officer cannot see the user's private objects, so it cannot set the
//! attribute on the KEK, and a key with `CKA_WRAP_WITH_TRUSTED` is refused by an untrusted KEK
//! (`CKR_KEY_NOT_WRAPPABLE`). A cloud HSM with an administrative role that can mark the key
//! should turn it on (see docs/key-service.md).

mod config;
mod error;
mod hsm;
mod keys;

pub use config::Pkcs11Config;
pub use hsm::{Pkcs11Hsm, SoftHsm};

/// What `orbyn keyservice init` does: makes the KEK and identity version 1 in the HSM the
/// environment names, and returns the identity's public key. Refuses if they exist.
pub fn init_from_env() -> Result<[u8; 32], String> {
    let config = Pkcs11Config::from_env()?;
    let hsm = Pkcs11Hsm::open(&config).map_err(|e| e.to_string())?;
    crate::KeyService::new(hsm)
        .init()
        .map_err(|e| e.to_string())
}
