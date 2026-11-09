use crate::{HsmError, HsmSetup};
use cryptoki::error::{Error as CkError, RvError};

pub(super) fn failed(err: CkError) -> HsmError {
    // The causes an operator can fix get their own variant; anything else keeps its text, which
    // never holds the PIN or a key.
    match &err {
        CkError::LibraryLoading(_) | CkError::MissingSymbol(_) => HsmError::Setup(HsmSetup::Module),
        CkError::Pkcs11(rv, _) => match rv {
            RvError::SlotIdInvalid => HsmError::Setup(HsmSetup::Slot),
            RvError::PinIncorrect
            | RvError::PinInvalid
            | RvError::PinLenRange
            | RvError::PinExpired
            | RvError::PinLocked => HsmError::Setup(HsmSetup::Pin),
            RvError::TokenNotPresent | RvError::TokenNotRecognized | RvError::DeviceRemoved => {
                HsmError::Setup(HsmSetup::Unreachable)
            }
            other => HsmError::Rv(ckr_name(other)),
        },
        _ => HsmError::Failed(err.to_string()),
    }
}

/// A return code's name as PKCS#11 writes it: `DeviceError` is `CKR_DEVICE_ERROR`.
fn ckr_name(rv: &RvError) -> String {
    let debug = format!("{rv:?}");
    // Only the variant's name, whatever the type prints after it.
    let name = debug.split(['(', ' ', '{']).next().unwrap_or("");
    let mut out = String::from("CKR");
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(ch.to_ascii_uppercase());
    }
    out
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn a_return_code_is_named_as_pkcs11_writes_it() {
        assert_eq!(ckr_name(&RvError::DeviceError), "CKR_DEVICE_ERROR");
        assert_eq!(ckr_name(&RvError::FunctionFailed), "CKR_FUNCTION_FAILED");
        assert_eq!(
            ckr_name(&RvError::CryptokiNotInitialized),
            "CKR_CRYPTOKI_NOT_INITIALIZED"
        );
        assert_eq!(ckr_name(&RvError::GeneralError), "CKR_GENERAL_ERROR");
    }

    #[test]
    fn the_causes_an_operator_can_fix_are_not_reported_as_return_codes() {
        let pkcs = |rv| {
            failed(CkError::Pkcs11(
                rv,
                cryptoki::context::Function::OpenSession,
            ))
        };
        assert_eq!(
            pkcs(RvError::SlotIdInvalid),
            HsmError::Setup(crate::HsmSetup::Slot)
        );
        assert_eq!(
            pkcs(RvError::PinIncorrect),
            HsmError::Setup(crate::HsmSetup::Pin)
        );
        assert_eq!(
            pkcs(RvError::PinLocked),
            HsmError::Setup(crate::HsmSetup::Pin)
        );
        assert_eq!(
            pkcs(RvError::TokenNotPresent),
            HsmError::Setup(crate::HsmSetup::Unreachable)
        );
        assert_eq!(
            pkcs(RvError::DeviceError),
            HsmError::Rv("CKR_DEVICE_ERROR".into())
        );
    }
}
