//! `verifyServiceKey`: the account's service key checked against the log, as the host calls it.
//!
//! The host fetches the answers from the key service's public API (never through the record
//! server) and passes them as they were served, with the pins from its configuration, the head it
//! saw last and the key it already verified. Nothing is kept here: the host stores `verified.seen`
//! and `verified.public_key` and passes them back next time (and, in the end, gossips them through
//! the private system zone).
//!
//! Bytes are base64url, as everywhere else in this crate, except the log's own roots in `seen`,
//! which are hex as the log API writes them. A refusal is data, not an error: it says whether the
//! host shows a possible-takeover warning, asks the person about their clock, or fetches again.

use super::*;
use orbyn_client::{
    LogAnswers, Pins, Seen, ServiceKeyPins, VerifiedServiceKey, verify_service_key as check,
};
use serde::Deserialize;

/// A pinned key, by the version it was published under.
#[derive(Deserialize)]
struct VersionedKey {
    version: u32,
    /// Base64url (32 bytes).
    key: String,
}

/// What a device pins in its configuration: the log and witness keys, and the key service's
/// identity keys by version.
#[derive(Deserialize)]
struct PinsJson {
    log_keys: Vec<VersionedKey>,
    /// Base64url (32 bytes), each.
    witnesses: Vec<String>,
    /// More than half of `witnesses`.
    threshold: usize,
    identity_keys: Vec<VersionedKey>,
}

/// What `GET /v1/log/lookup/{key}`, `GET /v1/log/entries` and `GET /v1/log/consistency` served,
/// as JSON text.
#[derive(Deserialize)]
struct AnswersJson {
    lookup: String,
    #[serde(default)]
    entry_pages: Vec<String>,
    consistency: Option<String>,
}

/// The newest head a device verified, as `verified.seen` gave it.
#[derive(Deserialize, Serialize)]
struct SeenJson {
    size: u64,
    /// Hex (32 bytes).
    log_root: String,
    service_map_root: String,
    identity_map_root: String,
    witnessed_ms: u64,
}

/// What `verifyServiceKey` takes.
#[derive(Deserialize)]
struct CheckJson {
    pins: PinsJson,
    /// The account's UUID.
    account_id: String,
    /// The certification the record server offered (`GET /v1/keychain/service-key`).
    offered: wire::ServiceKeyCertification,
    answers: AnswersJson,
    /// The service key this account's devices already verified, base64url (33 bytes), or `null`
    /// the first time (trust on first use).
    known_key: Option<String>,
    seen: Option<SeenJson>,
    /// The device's wall clock, milliseconds.
    now: f64,
}

/// A service key the log agrees with. Pass `seen` and `public_key` back next time.
#[derive(Serialize)]
struct VerifiedJson {
    identity_version: u32,
    /// Base64url (33 bytes).
    public_key: String,
    /// Base64url (32 bytes): what a service envelope names.
    statement_hash: String,
    entry_index: u64,
    seen: SeenJson,
}

/// Why the key was not accepted. `takeover` says whether a host shows a possible-takeover
/// warning; `code` is the stable name a host branches on.
#[derive(Serialize)]
struct RefusalJson {
    code: &'static str,
    takeover: bool,
    message: String,
}

#[derive(Serialize)]
struct VerdictJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<VerifiedJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<RefusalJson>,
}

impl PinsJson {
    fn into_pins(self) -> Result<ServiceKeyPins> {
        let mut log_keys = Vec::with_capacity(self.log_keys.len());
        for key in self.log_keys {
            log_keys.push((key.version, key32(&key.key)?));
        }
        let mut witnesses = Vec::with_capacity(self.witnesses.len());
        for witness in &self.witnesses {
            witnesses.push(key32(witness)?);
        }
        let mut identity_keys = Vec::with_capacity(self.identity_keys.len());
        for key in self.identity_keys {
            identity_keys.push((key.version, key32(&key.key)?));
        }
        Ok(ServiceKeyPins {
            log: Pins {
                log_keys,
                witnesses,
                threshold: self.threshold,
            },
            identity_keys,
        })
    }
}

impl SeenJson {
    fn to_seen(&self) -> Result<Seen> {
        Ok(Seen {
            size: self.size,
            log_root: hex32(&self.log_root)?,
            service_map_root: hex32(&self.service_map_root)?,
            identity_map_root: hex32(&self.identity_map_root)?,
            witnessed_ms: self.witnessed_ms,
        })
    }
}

impl From<Seen> for SeenJson {
    fn from(seen: Seen) -> Self {
        Self {
            size: seen.size,
            log_root: hex(&seen.log_root),
            service_map_root: hex(&seen.service_map_root),
            identity_map_root: hex(&seen.identity_map_root),
            witnessed_ms: seen.witnessed_ms,
        }
    }
}

impl From<VerifiedServiceKey> for VerifiedJson {
    fn from(verified: VerifiedServiceKey) -> Self {
        Self {
            identity_version: verified.identity_version,
            public_key: URL_SAFE_NO_PAD.encode(verified.public_key),
            statement_hash: URL_SAFE_NO_PAD.encode(verified.statement_hash),
            entry_index: verified.entry_index,
            seen: SeenJson::from(verified.seen),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    let bad = || error("invalid_input", "a log root is 32 bytes in hex");
    if text.len() != 64 || !text.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn key33(text: &str) -> Result<[u8; 33]> {
    unb64(text)?
        .try_into()
        .map_err(|_| error("invalid_input", "a service key is 33 bytes"))
}

/// Checks the account's service key against the log; returns `{verified}` or `{refusal}`. The
/// device escrows a zone key to the service key only when `verified` is present.
#[wasm_bindgen(js_name = verifyServiceKey)]
pub fn verify_service_key(input_json: &str) -> Result<String> {
    let input: CheckJson = parse(input_json)?;
    let pins = input.pins.into_pins()?;
    let account = uuid_bytes(&input.account_id)?;
    let known = match &input.known_key {
        Some(text) => Some(key33(text)?),
        None => None,
    };
    let seen = input.seen.as_ref().map(SeenJson::to_seen).transpose()?;
    let pages: Vec<&str> = input
        .answers
        .entry_pages
        .iter()
        .map(String::as_str)
        .collect();
    let answers = LogAnswers {
        lookup: &input.answers.lookup,
        entry_pages: &pages,
        consistency: input.answers.consistency.as_deref(),
    };
    let verdict = match check(
        &pins,
        account,
        &input.offered,
        &answers,
        known.as_ref(),
        seen.as_ref(),
        millis(input.now),
    ) {
        Ok(verified) => VerdictJson {
            verified: Some(verified.into()),
            refusal: None,
        },
        Err(refusal) => VerdictJson {
            verified: None,
            refusal: Some(RefusalJson {
                code: refusal.code(),
                takeover: refusal.is_takeover(),
                message: refusal.to_string(),
            }),
        },
    };
    to_json(&verdict)
}
