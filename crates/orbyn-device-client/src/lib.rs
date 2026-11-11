//! The native device client. A host (the Engineering app) supplies three things: a [`DeviceApi`]
//! (the transport; [`HttpApi`] is the real one), a [`KeyStore`] (where the device's secrets live,
//! the OS keychain in the app) and a [`Clock`]. [`DeviceClient`] does the rest. The design is
//! `docs/device-client.md`.

mod api;
mod client;
mod clock;
mod error;
mod signup;
mod store;

pub use api::{DeviceApi, HttpApi, Method, Request, Response, is_loopback_literal};
pub use client::{
    ClientConfig, DeviceClient, Password, SecondFactor, SecondFactorChallenge, SessionInfo,
    SignInOutcome, SignUpRequest,
};
pub use clock::{Clock, SystemClock};
pub use error::{DeviceError, StoreError};
pub use signup::PendingSignUp;
pub use store::{KeyStore, MemoryStore, StoredIdentity, StoredSession};
