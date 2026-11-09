use std::path::PathBuf;
use zeroize::Zeroizing;

/// Where the HSM is: the PKCS#11 module, the slot and the user PIN (a secret).
#[derive(Clone)]
pub struct Pkcs11Config {
    pub module: PathBuf,
    pub slot: u64,
    /// The user PIN, wiped from memory when the configuration is dropped.
    pub pin: Zeroizing<String>,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module", &self.module)
            .field("slot", &self.slot)
            .field("pin", &"(hidden)")
            .finish()
    }
}

impl Pkcs11Config {
    /// Reads `ORBYN_HSM_MODULE`, `ORBYN_HSM_SLOT` and `ORBYN_HSM_PIN`. The errors name the
    /// setting and never echo the PIN.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let need = |name: &str| {
            lookup(name)
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| format!("{name} is not set"))
        };
        Ok(Self {
            module: PathBuf::from(need("ORBYN_HSM_MODULE")?),
            slot: need("ORBYN_HSM_SLOT")?
                .trim()
                .parse()
                .map_err(|_| "ORBYN_HSM_SLOT is not a slot number".to_owned())?,
            pin: Zeroizing::new(need("ORBYN_HSM_PIN")?),
        })
    }
}
