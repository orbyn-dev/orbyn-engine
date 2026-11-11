//! The notices stream against a hand-made WebSocket server: it signs in first, answers pings,
//! reconnects after a drop and stops when the server rejects the session.

use futures_util::{SinkExt, StreamExt};
use orbyn_contracts::DevicePlatform;
use orbyn_device_client::{
    ClientConfig, DeviceClient, HttpApi, KeyStore, MemoryStore, Notice, NoticeConfig,
    StoredIdentity, StoredSession, SystemClock,
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

async fn client_for(address: &str) -> DeviceClient<HttpApi, MemoryStore, SystemClock> {
    let store = MemoryStore::new();
    store
        .save(&StoredIdentity {
            device_keys: Zeroizing::new([3u8; 64]),
            account_id: "account".to_owned(),
            device_id: "device".to_owned(),
            email: "a@example.test".to_owned(),
            session: Some(StoredSession {
                token: Zeroizing::new("the-token".to_owned()),
                expires_at: "2027-01-01T00:00:00Z".to_owned(),
            }),
            vault_key: Zeroizing::new([4u8; 32]),
        })
        .expect("save");
    DeviceClient::new(
        HttpApi::new(address).expect("loopback"),
        store,
        SystemClock,
        ClientConfig {
            device_name: "Laptop".to_owned(),
            platform: DevicePlatform::Linux,
            app: None,
        },
    )
}

fn quick() -> NoticeConfig {
    NoticeConfig {
        first_delay: Duration::from_millis(20),
        max_delay: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
    }
}

async fn next(notices: &mut orbyn_device_client::Notices) -> Notice {
    tokio::time::timeout(Duration::from_secs(5), notices.next())
        .await
        .expect("a notice in time")
        .expect("the stream is open")
}

#[tokio::test(flavor = "multi_thread")]
async fn it_signs_in_first_answers_pings_and_reconnects_after_a_drop() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    let server = tokio::spawn(async move {
        let mut auths = Vec::new();
        // First connection: sign-in, ready, a ping that must be answered, a notice, then a drop.
        let (stream, _) = listener.accept().await.expect("accept");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let Some(Ok(Message::Text(first))) = socket.next().await else {
            panic!("no auth")
        };
        auths.push(first.to_string());
        socket
            .send(Message::text(r#"{"type":"ready","device_id":"device"}"#))
            .await
            .expect("ready");
        socket
            .send(Message::Ping(b"are you there".to_vec().into()))
            .await
            .expect("ping");
        let pong = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = socket.next().await {
                if let Message::Pong(data) = message {
                    return Some(data);
                }
            }
            None
        })
        .await
        .expect("a pong in time");
        assert_eq!(pong.as_deref(), Some(&b"are you there"[..]));
        socket
            .send(Message::text(
                r#"{"type":"zone_changed","zone":"engineering.settings","token":"t1"}"#,
            ))
            .await
            .expect("notice");
        drop(socket);
        // Second connection: the stream came back by itself, signed in again.
        let (stream, _) = listener.accept().await.expect("accept again");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let Some(Ok(Message::Text(second))) = socket.next().await else {
            panic!("no auth")
        };
        auths.push(second.to_string());
        socket
            .send(Message::text(r#"{"type":"ready","device_id":"device"}"#))
            .await
            .expect("ready");
        socket
            .send(Message::text(r#"{"type":"resync"}"#))
            .await
            .expect("resync");
        tokio::time::sleep(Duration::from_millis(300)).await;
        auths
    });
    let client = client_for(&address).await;
    let mut notices = client.notices(quick()).expect("stream");
    assert_eq!(next(&mut notices).await, Notice::Connected);
    assert_eq!(
        next(&mut notices).await,
        Notice::ZoneChanged {
            zone: "engineering.settings".to_owned(),
            token: "t1".to_owned()
        }
    );
    assert_eq!(next(&mut notices).await, Notice::Disconnected);
    assert_eq!(next(&mut notices).await, Notice::Connected);
    assert_eq!(next(&mut notices).await, Notice::Resync);
    let auths = server.await.expect("server");
    for auth in auths {
        assert_eq!(auth, r#"{"type":"auth","token":"the-token"}"#);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_session_stops_the_stream_and_a_dropped_stream_closes_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let _ = socket.next().await;
        socket
            .send(Message::text(
                r#"{"type":"error","code":"unauthorized","message":"no"}"#,
            ))
            .await
            .expect("error");
        // Keep the socket open: the stream must stop on its own.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let client = client_for(&address).await;
    let mut notices = client.notices(quick()).expect("stream");
    assert_eq!(
        next(&mut notices).await,
        Notice::Rejected {
            code: "unauthorized".to_owned()
        }
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), notices.next())
            .await
            .expect("ends"),
        None
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_session_or_an_address_there_is_no_stream() {
    let client = client_for("http://127.0.0.1:9").await;
    client.sign_out(false).await.expect("sign out");
    assert_eq!(
        client.notices(quick()).err(),
        Some(orbyn_device_client::DeviceError::NotSignedIn)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_that_reaches_ready_starts_the_delay_over() {
    // The server accepts three connections, each says ready and drops. With the delay reset by
    // each ready, the pause before the third is as short as the pause before the second (about
    // 200 ms); without it, the second pause has doubled (about 400 ms).
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    let server = tokio::spawn(async move {
        let mut at = Vec::new();
        for _ in 0..3 {
            let (stream, _) = listener.accept().await.expect("accept");
            at.push(std::time::Instant::now());
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("handshake");
            let _ = socket.next().await;
            socket
                .send(Message::text(r#"{"type":"ready","device_id":"device"}"#))
                .await
                .expect("ready");
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(socket);
        }
        at
    });
    let config = NoticeConfig {
        first_delay: Duration::from_millis(200),
        max_delay: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
    };
    let client = client_for(&address).await;
    let _notices = client.notices(config).expect("stream");
    let at = server.await.expect("server");
    let first = at[1].duration_since(at[0]);
    let second = at[2].duration_since(at[1]);
    assert!(first >= Duration::from_millis(150), "{first:?}");
    assert!(
        second < Duration::from_millis(330),
        "the delay was not reset: {second:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_never_answers_the_handshake_is_given_up_on() {
    // Accepts the TCP connection and says nothing: without a connect timeout the stream hangs.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let config = NoticeConfig {
        connect_timeout: Duration::from_millis(150),
        ..quick()
    };
    let client = client_for(&address).await;
    let mut notices = client.notices(config).expect("stream");
    assert_eq!(next(&mut notices).await, Notice::Disconnected);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transport_that_reports_a_plain_text_address_off_loopback_gets_no_stream() {
    use orbyn_device_client::{DeviceApi, DeviceError, Request, Response};
    struct Remote;
    impl DeviceApi for Remote {
        async fn send(&self, _: Request) -> Result<Response, DeviceError> {
            Err(DeviceError::Transport)
        }
        fn base_url(&self) -> Option<&str> {
            Some("http://example.com")
        }
    }
    let store = MemoryStore::new();
    store
        .save(&StoredIdentity {
            device_keys: Zeroizing::new([3u8; 64]),
            account_id: "a".to_owned(),
            device_id: "d".to_owned(),
            email: "a@example.test".to_owned(),
            session: Some(StoredSession {
                token: Zeroizing::new("t".to_owned()),
                expires_at: String::new(),
            }),
            vault_key: Zeroizing::new([4u8; 32]),
        })
        .expect("save");
    let client = DeviceClient::new(
        Remote,
        store,
        SystemClock,
        ClientConfig {
            device_name: "x".to_owned(),
            platform: DevicePlatform::Linux,
            app: None,
        },
    );
    assert!(matches!(
        client.notices(quick()),
        Err(DeviceError::InvalidInput(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_message_ends_the_connection_instead_of_being_read() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let _ = socket.next().await;
        socket
            .send(Message::text(r#"{"type":"ready","device_id":"device"}"#))
            .await
            .expect("ready");
        let big = format!(
            r#"{{"type":"zone_changed","zone":"{}","token":"t"}}"#,
            "z".repeat(200_000)
        );
        let _ = socket.send(Message::text(big)).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let config = NoticeConfig {
        first_delay: Duration::from_secs(30),
        ..quick()
    };
    let client = client_for(&address).await;
    let mut notices = client.notices(config).expect("stream");
    assert_eq!(next(&mut notices).await, Notice::Connected);
    assert_eq!(
        next(&mut notices).await,
        Notice::Disconnected,
        "no notice came from the huge frame"
    );
}
