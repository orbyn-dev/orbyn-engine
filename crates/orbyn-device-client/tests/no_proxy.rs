//! The real transport never goes through a proxy named in the environment. A request to the
//! engine carries a bearer token, so a `HTTP_PROXY` or `ALL_PROXY` set on the machine (by
//! software, a profile or an attacker) must not be able to see it, even for a loopback address.
//!
//! The environment is process-wide, so each case runs the same test binary again as a child with
//! the proxy variables set. A loopback server stands for the engine and a second listener for the
//! proxy; the proxy must get no connection.

use orbyn_device_client::{DeviceApi, HttpApi, Method, Request, Zeroizing};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CHILD: &str = "ORBYN_NO_PROXY_CHILD";

/// A listener that counts connections and answers `status`.
async fn listener(status: &'static str) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let _ = socket.read(&mut buffer).await;
                let reply =
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (address, count)
}

/// Runs in the child: one authenticated request to the address in the environment.
#[tokio::test(flavor = "multi_thread")]
async fn child_sends_one_request() {
    let Ok(address) = std::env::var(CHILD) else {
        return; // Not a child: nothing to do.
    };
    let response = HttpApi::new(&address)
        .expect("loopback http is allowed")
        .send(Request {
            method: Method::Get,
            path: "/v1/devices".to_owned(),
            bearer: Some(Zeroizing::new("secret-token".to_owned())),
            body: None,
        })
        .await
        .expect("an answer");
    assert_eq!(response.status, 204, "the answer came from the engine");
}

fn child(engine: &str, proxy: &str, variables: &[&str], no_proxy: Option<&str>) -> bool {
    let mut command = Command::new(std::env::current_exe().expect("this test binary"));
    command
        .args(["--exact", "child_sends_one_request", "--nocapture"])
        .env(CHILD, engine);
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(name);
    }
    for name in variables {
        command.env(name, proxy);
    }
    if let Some(no_proxy) = no_proxy {
        command.env("NO_PROXY", no_proxy).env("no_proxy", no_proxy);
    }
    command.status().expect("the child ran").success()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proxy_in_the_environment_never_sees_a_request_to_the_engine() {
    if std::env::var(CHILD).is_ok() {
        return; // The child runs only `child_sends_one_request`.
    }
    for (variables, no_proxy) in [
        (&["HTTP_PROXY", "http_proxy"][..], None),
        (&["ALL_PROXY", "all_proxy"][..], None),
        (&["HTTPS_PROXY", "https_proxy"][..], None),
        (
            &["HTTP_PROXY", "ALL_PROXY"][..],
            // A NO_PROXY that does not name the engine's address changes nothing.
            Some("example.com"),
        ),
    ] {
        let (engine, reached_engine) = listener("204 No Content").await;
        let (proxy, reached_proxy) = listener("502 Bad Gateway").await;
        let (engine_for_child, proxy_for_child) = (engine.clone(), proxy.clone());
        let ok = tokio::task::spawn_blocking(move || {
            child(&engine_for_child, &proxy_for_child, variables, no_proxy)
        })
        .await
        .expect("joined");
        assert_eq!(
            reached_proxy.load(Ordering::SeqCst),
            0,
            "{variables:?} NO_PROXY={no_proxy:?}: the proxy was contacted"
        );
        assert!(ok, "{variables:?}: the request did not reach the engine");
        assert_eq!(reached_engine.load(Ordering::SeqCst), 1, "{variables:?}");
    }
}
