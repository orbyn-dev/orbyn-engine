//! The password type.

use zeroize::Zeroizing;

/// A password. Wiped when dropped, and its `Debug` prints `Password(..)` whatever version of
/// `zeroize` a build resolves (older ones print the contents of a bare `Zeroizing<String>`).
#[derive(Clone)]
pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(text: impl Into<String>) -> Self {
        Self(Zeroizing::new(text.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Password {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
}
