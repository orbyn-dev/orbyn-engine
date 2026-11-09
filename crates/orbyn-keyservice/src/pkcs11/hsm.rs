use super::config::Pkcs11Config;
use super::error::failed;
use super::keys::{
    ED25519_PARAMS, KEK_LABEL, P256_PARAMS, Use, ed25519_public, identity_label, log_key_label,
    private_usage, public_usage, secret_usage,
};
use crate::{Hsm, HsmError, HsmMessage, MessageKind, SessionKey, WrappedAccountKey};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use orbyn_crypto::P256Point;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

/// A PKCS#11 HSM. Each operation opens its own session and logs in as the user; an unwrapped
/// account key lives in the session that made it until it is destroyed.
pub struct Pkcs11Hsm {
    context: Arc<Pkcs11>,
    slot: Slot,
    pin: AuthPin,
    sessions: Mutex<HashMap<u64, (Session, ObjectHandle)>>,
    next: Mutex<u64>,
}

/// SoftHSM is a PKCS#11 module; this is the same type.
pub type SoftHsm = Pkcs11Hsm;

impl Pkcs11Hsm {
    /// Loads the module and initialises it.
    pub fn open(config: &Pkcs11Config) -> Result<Self, HsmError> {
        let context = Pkcs11::new(&config.module).map_err(failed)?;
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(err) => return Err(failed(err)),
        }
        let slot = Slot::try_from(config.slot).map_err(|_| HsmError::Failed("bad slot".into()))?;
        Ok(Self::with_context(Arc::new(context), slot, &config.pin))
    }

    /// Uses a module that is already loaded and initialised, shared with other users of it.
    pub fn with_context(context: Arc<Pkcs11>, slot: Slot, pin: &str) -> Self {
        Self {
            context,
            slot,
            pin: AuthPin::from(pin.to_owned()),
            sessions: Mutex::new(HashMap::new()),
            next: Mutex::new(0),
        }
    }

    fn live(&self) -> MutexGuard<'_, HashMap<u64, (Session, ObjectHandle)>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many unwrapped keys are live as session objects.
    pub fn live_session_objects(&self) -> usize {
        self.live().len()
    }

    /// A logged-in session, for tests that look at what the HSM refuses (attribute reads of
    /// private keys, wrapping a non-extractable key). Only with `test-support`.
    #[cfg(feature = "test-support")]
    pub fn raw_session(&self) -> Result<Session, HsmError> {
        self.session()
    }

    /// Attributes of an unwrapped session key, as the HSM reports them. Only with `test-support`.
    #[cfg(feature = "test-support")]
    pub fn session_key_attribute_values(
        &self,
        key: &SessionKey,
        types: &[AttributeType],
    ) -> Result<Vec<Attribute>, HsmError> {
        let live = self.live();
        let (session, handle) = live.get(&key.0).ok_or(HsmError::NotFound)?;
        session.get_attributes(*handle, types).map_err(failed)
    }

    /// Whether an unwrapped session key is on the token, extractable and sensitive, as the HSM
    /// reports it. Only with `test-support`.
    #[cfg(feature = "test-support")]
    pub fn session_key_attributes(&self, key: &SessionKey) -> Result<(bool, bool, bool), HsmError> {
        let live = self.live();
        let (session, handle) = live.get(&key.0).ok_or(HsmError::NotFound)?;
        let attrs = session
            .get_attributes(
                *handle,
                &[
                    AttributeType::Token,
                    AttributeType::Extractable,
                    AttributeType::Sensitive,
                ],
            )
            .map_err(failed)?;
        let (mut token, mut extractable, mut sensitive) = (true, true, false);
        for attr in attrs {
            match attr {
                Attribute::Token(v) => token = v,
                Attribute::Extractable(v) => extractable = v,
                Attribute::Sensitive(v) => sensitive = v,
                _ => {}
            }
        }
        Ok((token, extractable, sensitive))
    }

    fn session(&self) -> Result<Session, HsmError> {
        let session = self.context.open_rw_session(self.slot).map_err(failed)?;
        match session.login(UserType::User, Some(&self.pin)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(err) => Err(failed(err)),
        }
    }

    fn find(
        session: &Session,
        class: ObjectClass,
        label: &[u8],
    ) -> Result<Option<ObjectHandle>, HsmError> {
        let found = session
            .find_objects(&[Attribute::Class(class), Attribute::Label(label.to_vec())])
            .map_err(failed)?;
        Ok(found.into_iter().next())
    }

    fn kek(session: &Session) -> Result<ObjectHandle, HsmError> {
        Self::find(session, ObjectClass::SECRET_KEY, KEK_LABEL)?.ok_or(HsmError::NotFound)
    }

    /// Makes an Ed25519 signing key pair labelled `label`: non-extractable, for signing only.
    fn generate_signing_key(&self, label: Vec<u8>) -> Result<[u8; 32], HsmError> {
        let session = self.session()?;
        if Self::find(&session, ObjectClass::PRIVATE_KEY, &label)?.is_some() {
            return Err(HsmError::AlreadyExists);
        }
        let mut public_template = vec![
            Attribute::Token(true),
            Attribute::EcParams(ED25519_PARAMS.to_vec()),
            Attribute::Label(label.clone()),
        ];
        public_template.extend(public_usage(&[Use::Verify]));
        let mut private_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Label(label),
        ];
        private_template.extend(private_usage(&[Use::Sign]));
        let (public, _private) = session
            .generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(failed)?;
        ed25519_public(&Self::point_of(&session, public)?)
    }

    /// The public key labelled `label`.
    fn signing_public(&self, label: &[u8]) -> Result<[u8; 32], HsmError> {
        let session = self.session()?;
        let public =
            Self::find(&session, ObjectClass::PUBLIC_KEY, label)?.ok_or(HsmError::NotFound)?;
        ed25519_public(&Self::point_of(&session, public)?)
    }

    fn point_of(session: &Session, public: ObjectHandle) -> Result<Vec<u8>, HsmError> {
        let attrs = session
            .get_attributes(public, &[AttributeType::EcPoint])
            .map_err(failed)?;
        match attrs.into_iter().next() {
            Some(Attribute::EcPoint(point)) => Ok(point),
            _ => Err(HsmError::BadKey),
        }
    }
}

impl crate::sealed::Sealed for Pkcs11Hsm {}

impl Hsm for Pkcs11Hsm {
    fn kek_exists(&self) -> Result<bool, HsmError> {
        let session = self.session()?;
        Ok(Self::find(&session, ObjectClass::SECRET_KEY, KEK_LABEL)?.is_some())
    }

    fn generate_kek(&self) -> Result<(), HsmError> {
        let session = self.session()?;
        if Self::find(&session, ObjectClass::SECRET_KEY, KEK_LABEL)?.is_some() {
            return Err(HsmError::AlreadyExists);
        }
        let mut template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::ValueLen(32.into()),
            Attribute::Label(KEK_LABEL.to_vec()),
        ];
        template.extend(secret_usage(&[Use::Wrap, Use::Unwrap]));
        session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(failed)?;
        Ok(())
    }

    fn identity_exists(&self, version: u32) -> Result<bool, HsmError> {
        let session = self.session()?;
        Ok(Self::find(&session, ObjectClass::PRIVATE_KEY, &identity_label(version))?.is_some())
    }

    fn generate_identity(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.generate_signing_key(identity_label(version))
    }

    fn identity_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.signing_public(&identity_label(version))
    }

    fn generate_log_key(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.generate_signing_key(log_key_label(version))
    }

    fn log_key_exists(&self, version: u32) -> Result<bool, HsmError> {
        let session = self.session()?;
        Ok(Self::find(&session, ObjectClass::PRIVATE_KEY, &log_key_label(version))?.is_some())
    }

    fn log_key_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.signing_public(&log_key_label(version))
    }

    fn sign(&self, version: u32, message: &HsmMessage) -> Result<[u8; 64], HsmError> {
        // The key set follows the message's kind.
        let label = match message.kind() {
            MessageKind::ServiceKeyStatement => identity_label(version),
            MessageKind::LogHead => log_key_label(version),
        };
        let session = self.session()?;
        let key =
            Self::find(&session, ObjectClass::PRIVATE_KEY, &label)?.ok_or(HsmError::NotFound)?;
        let signature = session
            .sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                key,
                message.signed_bytes(),
            )
            .map_err(failed)?;
        signature.try_into().map_err(|_| HsmError::BadKey)
    }

    fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError> {
        let session = self.session()?;
        let kek = Self::kek(&session)?;
        // Session objects, never on the token. The private half must be extractable for the
        // wrap, and sensitive, so it can leave only wrapped.
        let mut public_template = vec![
            Attribute::Token(false),
            Attribute::EcParams(P256_PARAMS.to_vec()),
        ];
        public_template.extend(public_usage(&[]));
        let mut private_template = vec![
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
        ];
        private_template.extend(private_usage(&[Use::Derive]));
        let (public, private) = session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(failed)?;
        let result = (|| {
            let wrapped = session
                .wrap_key(&Mechanism::AesKeyWrapPad, kek, private)
                .map_err(failed)?;
            let point = P256Point::from_hsm_point(&Self::point_of(&session, public)?)
                .map_err(|_| HsmError::BadKey)?;
            Ok(WrappedAccountKey {
                wrapped,
                public: point,
            })
        })();
        // The private key is gone from the HSM whatever happened.
        let _ = session.destroy_object(private);
        let _ = session.destroy_object(public);
        result
    }

    fn unwrap_account_key(&self, wrapped: &[u8]) -> Result<SessionKey, HsmError> {
        let session = self.session()?;
        let kek = Self::kek(&session)?;
        let mut template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ];
        template.extend(private_usage(&[Use::Derive]));
        let handle = session
            .unwrap_key(&Mechanism::AesKeyWrapPad, kek, wrapped, &template)
            .map_err(failed)?;
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        let id = *next;
        *next += 1;
        self.live().insert(id, (session, handle));
        Ok(SessionKey(id))
    }

    fn derive(
        &self,
        key: &SessionKey,
        ephemeral: &P256Point,
    ) -> Result<Zeroizing<[u8; 32]>, HsmError> {
        let live = self.live();
        let (session, handle) = live.get(&key.0).ok_or(HsmError::NotFound)?;
        let peer = ephemeral.uncompressed();
        let mut template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32.into()),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        template.extend(secret_usage(&[]));
        let derived = session
            .derive_key(
                &Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &peer)),
                *handle,
                &template,
            )
            .map_err(failed)?;
        let value = session
            .get_attributes(derived, &[AttributeType::Value])
            .map_err(failed);
        let _ = session.destroy_object(derived);
        match value?.into_iter().next() {
            Some(Attribute::Value(bytes)) => {
                let bytes = Zeroizing::new(bytes);
                let mut out = Zeroizing::new([0u8; 32]);
                if bytes.len() != 32 {
                    return Err(HsmError::BadKey);
                }
                out.copy_from_slice(&bytes);
                Ok(out)
            }
            _ => Err(HsmError::BadKey),
        }
    }

    fn destroy(&self, key: SessionKey) -> Result<(), HsmError> {
        let (session, handle) = self.live().remove(&key.0).ok_or(HsmError::NotFound)?;
        let result = session.destroy_object(handle).map_err(failed);
        drop(session);
        result
    }
}
