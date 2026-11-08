//! The public API's settings and their refusals.

use orbyn_keyservice_daemon::{messages, public::PublicSettings};

fn parse(pairs: &[(&str, &str)]) -> Result<PublicSettings, String> {
    PublicSettings::parse(&|name| {
        pairs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| (*v).to_owned())
    })
}

#[test]
fn without_a_bind_there_is_no_public_api_and_nothing_else_is_needed() {
    assert_eq!(parse(&[]), Ok(PublicSettings::default()));
    assert_eq!(
        parse(&[("ORBYN_KS_PUBLIC_BIND", "  ")]),
        Ok(PublicSettings::default())
    );
}

#[test]
fn the_bind_the_header_and_the_origins_are_read() {
    let settings = parse(&[
        ("ORBYN_KS_PUBLIC_BIND", "0.0.0.0:8480"),
        ("ORBYN_KS_CLIENT_IP_HEADER", " CF-Connecting-IP "),
        (
            "ORBYN_KS_ALLOWED_ORIGINS",
            "https://a.example, https://b.example,,",
        ),
    ])
    .expect("settings");
    assert_eq!(
        settings.bind.as_ref().map(|(a, _)| a.to_string()),
        Some("0.0.0.0:8480".to_owned())
    );
    assert_eq!(
        settings.client_ip_header.as_ref().map(|h| h.as_str()),
        Some("cf-connecting-ip")
    );
    assert_eq!(
        settings.allowed_origins,
        vec!["https://a.example", "https://b.example"]
    );
}

#[test]
fn a_bad_bind_or_header_is_refused_with_its_own_message_naming_the_setting() {
    assert_eq!(
        parse(&[("ORBYN_KS_PUBLIC_BIND", "not an address")]),
        Err(messages::public_bind_invalid())
    );
    assert_eq!(
        parse(&[("ORBYN_KS_PUBLIC_BIND", "8480")]),
        Err(messages::public_bind_invalid())
    );
    assert_eq!(
        parse(&[("ORBYN_KS_CLIENT_IP_HEADER", "not a header")]),
        Err(messages::client_ip_header_invalid())
    );
    assert!(messages::public_bind_invalid().contains("ORBYN_KS_PUBLIC_BIND"));
    assert!(messages::client_ip_header_invalid().contains("ORBYN_KS_CLIENT_IP_HEADER"));
    assert!(messages::cannot_listen_public("0.0.0.0:8480").contains("ORBYN_KS_PUBLIC_BIND"));
    // The internal bind's setting is not touched.
    assert_ne!(messages::public_bind_invalid(), messages::bind_invalid());
}

#[test]
fn pruning_never_forgets_a_request_a_limit_still_counts() {
    use orbyn_keyservice_daemon::{RATE_RETENTION_SECS, RATE_WINDOW_SECS};
    // Every allowance counts over RATE_WINDOW_SECS (one hour); a row is kept at least that long.
    // (The same is also a compile-time assertion in the crate.)
    const {
        assert!(RATE_WINDOW_SECS == 3600);
        assert!(RATE_RETENTION_SECS >= RATE_WINDOW_SECS);
    }
}
