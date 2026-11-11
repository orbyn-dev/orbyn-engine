//! The app label a device may sign into its introduction.

use super::{AccountError, NewDevice, Result};
use orbyn_auth_client::{
    DEVICE_LOGIN_CONTEXT, DEVICE_LOGIN_V2_CONTEXT, DEVICE_REGISTER_CONTEXT,
    DEVICE_REGISTER_V2_CONTEXT, Descriptor, login_message, login_message_v2, register_message,
    register_message_v2,
};

/// The product a device belongs to, when it says so. It is signed with the device's
/// introduction, so a server or relay cannot relabel a device afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum App {
    Planner,
    Engineering,
}

impl App {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Engineering => "engineering",
        }
    }

    pub(super) fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "planner" => Self::Planner,
            "engineering" => Self::Engineering,
            _ => return Err(AccountError::Internal),
        })
    }

    pub(super) fn parse_opt(text: Option<&str>) -> Result<Option<Self>> {
        text.map(Self::parse).transpose()
    }
}

impl NewDevice {
    /// The context and bytes this device's sign-up signature must cover. A device that names its
    /// app signs the v2 message, which adds the trimmed name, platform and app; one that does not
    /// signs the v1 message, so older clients keep working.
    pub(super) fn register_proof(
        &self,
        name: &str,
        email: &str,
        upload: &[u8],
    ) -> (&'static str, Vec<u8>) {
        match self.app {
            Some(app) => (
                DEVICE_REGISTER_V2_CONTEXT,
                register_message_v2(email, upload, &self.keys, &self.descriptor(name, app)),
            ),
            None => (
                DEVICE_REGISTER_CONTEXT,
                register_message(email, upload, &self.keys),
            ),
        }
    }

    /// As [`Self::register_proof`], for a sign-in.
    pub(super) fn login_proof(&self, name: &str, login_id: &[u8; 16]) -> (&'static str, Vec<u8>) {
        match self.app {
            Some(app) => (
                DEVICE_LOGIN_V2_CONTEXT,
                login_message_v2(login_id, &self.keys, &self.descriptor(name, app)),
            ),
            None => (DEVICE_LOGIN_CONTEXT, login_message(login_id, &self.keys)),
        }
    }

    fn descriptor<'a>(&self, name: &'a str, app: App) -> Descriptor<'a> {
        Descriptor {
            name,
            platform: self.platform.as_str(),
            app: app.as_str(),
        }
    }
}
