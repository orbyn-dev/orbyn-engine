//! The client against the real engine on the local stack (`scripts/local.sh up`): an invite, a
//! sign-up with the emailed code, a second device that waits for approval, the re-login and
//! signing everyone out. Test data only.
//!
//! ```sh
//! scripts/local.sh up
//! ORBYN_LOCAL_STACK=1 cargo test -p orbyn-device-client --test local_stack -- --ignored
//! ```
//! The test is ignored **and** needs `ORBYN_LOCAL_STACK=1`: CI runs `--include-ignored` without a
//! local stack, and there the test prints a note and passes without doing anything.
//! `ORBYN_LOCAL_URL` changes the address (default `http://127.0.0.1:8080`).

use orbyn_contracts::{DevicePlatform, DeviceState};
use orbyn_device_client::{
    ClientConfig, DeviceClient, DeviceError, HttpApi, MemoryStore, SignInOutcome, SignUpRequest,
    SystemClock,
};
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroizing;

fn script(args: &[&str]) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/local.sh");
    let out = Command::new("bash")
        .arg(path)
        .args(args)
        .output()
        .expect("scripts/local.sh runs");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn client(name: &str) -> DeviceClient<HttpApi, MemoryStore, SystemClock> {
    let address =
        std::env::var("ORBYN_LOCAL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
    DeviceClient::new(
        HttpApi::new(&address).expect("a loopback address"),
        MemoryStore::new(),
        SystemClock,
        ClientConfig {
            device_name: name.to_owned(),
            platform: DevicePlatform::Linux,
        },
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the local stack: scripts/local.sh up"]
async fn sign_up_second_device_re_login_and_sign_out_everywhere() {
    if std::env::var("ORBYN_LOCAL_STACK").as_deref() != Ok("1") {
        eprintln!("skipped: set ORBYN_LOCAL_STACK=1 with the local stack up (scripts/local.sh up)");
        return;
    }
    let password = Zeroizing::new("correct horse battery staple".to_owned());
    let email = format!("e2e-{}@example.test", uuid::Uuid::new_v4().simple());
    let invite = script(&["invite-code", "device-client"]);
    assert_eq!(invite.len(), 19, "an invite code: {invite:?}");

    // The first device signs up with the invite and the code from the worker's log.
    let first = client("First");
    let mut pending = first
        .begin_sign_up(SignUpRequest {
            email: email.clone(),
            password: password.clone(),
            invite: Some(invite),
        })
        .await
        .expect("begin");
    let mut code = String::new();
    for _ in 0..30 {
        code = script(&["latest-code", &email]);
        if !code.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(!code.is_empty(), "the worker logged no code for {email}");
    let session = first
        .verify_sign_up(&mut pending, &code)
        .await
        .expect("verify");
    assert_eq!(session.device_state, DeviceState::Trusted);

    // A second device signs in with the password and waits for approval.
    let second = client("Second");
    let outcome = second.sign_in(&email, &password).await.expect("sign in");
    let SignInOutcome::NeedsApproval(info) = outcome else {
        panic!("a new device is pending: {outcome:?}");
    };
    assert_eq!(info.device_state, DeviceState::Pending);
    assert_ne!(info.device_id, session.device_id);

    // A wrong password is refused on the device.
    let third = client("Third");
    assert_eq!(
        third
            .sign_in(&email, &Zeroizing::new("wrong horse".to_owned()))
            .await
            .err(),
        Some(DeviceError::LoginFailed)
    );

    // The first device signs in again as itself (a trusted start), and signs everyone out. The
    // sign-in just finished, so it is recent.
    let outcome = first.sign_in(&email, &password).await.expect("again");
    assert!(matches!(outcome, SignInOutcome::SignedIn(_)), "{outcome:?}");
    first.reauthenticate(&password).await.expect("re-login");
    first.sign_out_all().await.expect("sign out everywhere");
    assert_eq!(
        first.sign_out_all().await.err(),
        Some(DeviceError::NotSignedIn)
    );
}
