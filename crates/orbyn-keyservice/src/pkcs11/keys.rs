use crate::HsmError;
use cryptoki::object::Attribute;

/// DER of the P-256 curve OID, for `CKA_EC_PARAMS`.
pub(super) const P256_PARAMS: [u8; 10] =
    [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER of the Ed25519 OID (1.3.101.112), for `CKA_EC_PARAMS`.
pub(super) const ED25519_PARAMS: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
pub(super) const KEK_LABEL: &[u8] = b"orbyn-kek-v1";

pub(super) fn identity_label(version: u32) -> Vec<u8> {
    format!("orbyn-identity-v{version}").into_bytes()
}

/// The log key's label: a different set from the identities, so a version number alone cannot
/// reach the wrong key.
pub(super) fn log_key_label(version: u32) -> Vec<u8> {
    format!("orbyn-log-v{version}").into_bytes()
}

/// What a key may be used for. Every template sets **every** usage flag, true only for what the
/// key is for, so nothing depends on a token's default (some default to true).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Use {
    Sign,
    Verify,
    SignRecover,
    VerifyRecover,
    Encrypt,
    Decrypt,
    Wrap,
    Unwrap,
    Derive,
}

fn on(allowed: &[Use], what: Use) -> bool {
    allowed.contains(&what)
}

/// The flags of a secret key.
pub(super) fn secret_usage(allowed: &[Use]) -> Vec<Attribute> {
    vec![
        Attribute::Encrypt(on(allowed, Use::Encrypt)),
        Attribute::Decrypt(on(allowed, Use::Decrypt)),
        Attribute::Sign(on(allowed, Use::Sign)),
        Attribute::Verify(on(allowed, Use::Verify)),
        Attribute::Wrap(on(allowed, Use::Wrap)),
        Attribute::Unwrap(on(allowed, Use::Unwrap)),
        Attribute::Derive(on(allowed, Use::Derive)),
    ]
}

/// The flags of a private key.
pub(super) fn private_usage(allowed: &[Use]) -> Vec<Attribute> {
    vec![
        Attribute::Decrypt(on(allowed, Use::Decrypt)),
        Attribute::Sign(on(allowed, Use::Sign)),
        Attribute::SignRecover(on(allowed, Use::SignRecover)),
        Attribute::Unwrap(on(allowed, Use::Unwrap)),
        Attribute::Derive(on(allowed, Use::Derive)),
    ]
}

/// The flags of a public key.
pub(super) fn public_usage(allowed: &[Use]) -> Vec<Attribute> {
    vec![
        Attribute::Encrypt(on(allowed, Use::Encrypt)),
        Attribute::Verify(on(allowed, Use::Verify)),
        Attribute::VerifyRecover(on(allowed, Use::VerifyRecover)),
        Attribute::Wrap(on(allowed, Use::Wrap)),
    ]
}

/// The 32-byte Ed25519 public key from `CKA_EC_POINT`, which wraps it in a DER OCTET STRING.
pub(super) fn ed25519_public(point: &[u8]) -> Result<[u8; 32], HsmError> {
    let raw = match point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        other => other,
    };
    raw.try_into().map_err(|_| HsmError::BadKey)
}
