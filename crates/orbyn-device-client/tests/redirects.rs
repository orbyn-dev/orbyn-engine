//! The real transport never follows a redirect: a redirect could carry the bearer token to
//! another host. A loopback server answers every kind of redirect with a `Location` that points
//! at a second loopback listener, and that listener must never see a connection.

use orbyn_device_client::{DeviceApi, DeviceError, HttpApi, Method, Request, Zeroizing};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A listener that only counts the connections it accepts.
async fn counting_listener() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            // Answer, so a client that did follow would not hang.
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    });
    (address, count)
}

/// A server that answers every request with `status` and a `Location` to `target`.
async fn redirecting_listener(status: &'static str, target: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let target = target.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let _ = socket.read(&mut buffer).await;
                let reply = format!(
                    "HTTP/1.1 {status}\r\nLocation: {target}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    address
}

fn request(method: Method) -> Request {
    Request {
        method,
        path: "/v1/devices".to_owned(),
        bearer: Some(Zeroizing::new("secret-token".to_owned())),
        body: match method {
            Method::Get | Method::Delete => None,
            Method::Post | Method::Put => Some(Zeroizing::new(b"{}".to_vec())),
        },
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_returned_as_the_answer_and_the_target_is_never_contacted() {
    let (target, contacted) = counting_listener().await;
    for (status, code) in [
        ("301 Moved Permanently", 301),
        ("302 Found", 302),
        ("303 See Other", 303),
        ("307 Temporary Redirect", 307),
        ("308 Permanent Redirect", 308),
    ] {
        let first = redirecting_listener(status, target.clone()).await;
        let api = HttpApi::new(&first).expect("loopback http is allowed");
        // Every method, with the bearer token: 307 and 308 would repeat the body and the header.
        for method in [Method::Get, Method::Post, Method::Put, Method::Delete] {
            let response = api
                .send(request(method))
                .await
                .expect("the redirect is an answer, not followed");
            assert_eq!(response.status, code, "{status} {method:?}");
        }
    }
    // Give a follower time to connect, then check that nothing did.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        contacted.load(Ordering::SeqCst),
        0,
        "the redirect target was contacted"
    );
}

#[test]
fn plain_http_is_refused_for_any_host_that_is_not_a_loopback_ip_literal() {
    for refused in [
        "http://example.com",
        "http://localhost",
        "http://10.0.0.1",
        "http://192.168.1.5:8080",
        "http://[2001:db8::1]",
        "http://127.0.0.1.example.com",
    ] {
        assert!(
            matches!(HttpApi::new(refused), Err(DeviceError::InvalidInput(_))),
            "{refused}"
        );
    }
    for allowed in [
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "https://api.orbyn.dev",
    ] {
        assert!(HttpApi::new(allowed).is_ok(), "{allowed}");
    }
}
