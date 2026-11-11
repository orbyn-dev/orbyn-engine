//! A device's description as it signed it at sign-in.

use orbyn_auth_client as auth;
use orbyn_contracts as wire;

/// A device's name, platform and app as signed into its sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Described {
    name: String,
    platform: &'static str,
    app: &'static str,
}

impl Described {
    pub(crate) fn new(name: &str, platform: wire::DevicePlatform, app: wire::DeviceApp) -> Self {
        Self {
            name: name.trim().to_owned(),
            platform: platform.as_str(),
            app: app.as_str(),
        }
    }

    /// What the server lists for a device: a description only when it names an app.
    pub(crate) fn of(device: &wire::Device) -> Option<Self> {
        device
            .app
            .map(|app| Self::new(&device.name, device.platform, app))
    }

    pub(crate) fn view(&self) -> auth::Descriptor<'_> {
        auth::Descriptor {
            name: &self.name,
            platform: self.platform,
            app: self.app,
        }
    }
}
