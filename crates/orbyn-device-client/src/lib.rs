//! The native device client. A host (the Engineering app) supplies three things: a [`DeviceApi`]
//! (the transport; [`HttpApi`] is the real one), a [`KeyStore`] (where the device's secrets live,
//! the OS keychain in the app) and a [`Clock`]. [`DeviceClient`] does the rest. The design is
//! `docs/device-client.md`.

mod api;
mod approvals;
mod client;
mod clock;
mod error;
mod notices;
mod password;
mod signup;
mod status;
mod store;
mod sync;

pub use api::{DeviceApi, HttpApi, Method, Request, Response, is_loopback_literal};
pub use approvals::{ApproverApproval, ApproverState, JoinedApproval};
pub use client::{
    ClientConfig, DeviceClient, SecondFactor, SecondFactorChallenge, SessionInfo, SignInOutcome,
    SignUpRequest,
};
pub use clock::{Clock, SystemClock};
pub use error::{DeviceError, StoreError};
pub use notices::{Notice, NoticeConfig, Notices};
pub use password::Password;
pub use signup::PendingSignUp;
pub use status::{SyncState, SyncStatus};
pub use store::{KeyStore, MemoryStore, StoredIdentity, StoredSession};
pub use sync::{SyncReport, ZoneReport};

// Everything of another Engine crate that this crate's public API exposes, so the app names it
// from here and never depends on `orbyn-contracts` (rule D6). They are the same types, not copies.
// `orbyn-client` re-exports the contract types the engine's own signatures use.
pub use orbyn_client::{
    Applied, ClientError, Device, DeviceApp, DeviceKeys, DeviceList, DevicePlatform, DevicePublic,
    Engine, Fields, Local, Peer, PendingApproval, Quarantined, RefusedEnvelope, RejectedFields,
    Snapshot, Stamp, Trashed,
};
pub use orbyn_contracts::{DeviceRemoval, DeviceState};
pub use zeroize::Zeroizing;
