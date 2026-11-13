//! Checking the account's service key against the transparency log, before the device seals a
//! single zone key to it.
//!
//! The record server gives a device a certification ([`wire::ServiceKeyCertification`]). The server
//! cannot forge it (only the key service's HSM signs), but the key service's own operators could
//! certify a second key for the account, and only the log can show that. So the device also
//! fetches, from the key service's public API and not through the record server, the newest head,
//! the lookup proof of the **offered key** and its chain of entries, and [`verify_service_key`]
//! checks all of it:
//!
//! - the head: the pinned log key signed it, enough pinned witnesses cosigned it, and it is fresh
//!   by the witnesses' time (`orbyn_translog::verify`);
//! - that head against the last one this device saw: no rollback, no fork, a consistency proof;
//! - the account's chain under that head: whole, linked, and ending at the entry the map holds;
//! - the certification: every certification in the chain is for this account and this key, with
//!   identity versions that strictly rise (a re-signing under a newer identity is the only reason
//!   to certify the same key again), none after a retirement, the newest is signed by an identity
//!   key this device pinned for its version, and it is the one the record server offered; the key
//!   is not retired.
//!
//! **A second key is not caught by the log checks alone.** A second key certified for the same
//! account has its own map key and its own valid chain, so it verifies on its own. What catches it
//! is `known_key`: the key this account's devices already verified, which the host keeps locally
//! and (slice 8e) gossips through the private system zone. A different offered key is refused with
//! [`ServiceKeyRefusal::KeyChanged`]. With `known_key` `None` the check is **trust on first use**:
//! the first key the log agrees with is accepted, so a host must store the key it gets back and
//! pass it every time after.
//!
//! The answers have limits ([`MAX_ENTRY_PAGES`], and `orbyn_translog::verify` caps cosignatures).
//! A witness time ahead of the device's clock is [`ServiceKeyRefusal::ClockAhead`], a verdict about
//! the device and not the log: a host asks the person to check their clock and shows no takeover
//! warning.
//!
//! The device **escrows only on `Ok`**. Every `Err` is a verdict on the bytes, so a host shows a
//! possible-takeover warning for the ones that say the log is wrong, and treats a fetch that failed,
//! or a `503 no_published_head`, as availability: it never calls this and escrows nothing yet.
//!
//! No IO, no clock of its own and no randomness: the host passes the answers as the public API
//! served them (JSON, bytes in hex) and its wall clock.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_contracts as wire;
use orbyn_crypto::{P256Point, service_key_statement, service_key_statement_hash};
use orbyn_translog::entry::{KIND_SERVICE_KEY, KIND_SERVICE_KEY_RETIRE};
use orbyn_translog::verify::{self as log, ChainItem, Pins, Seen, SignedHead};
use orbyn_translog::{
    Cosignature, Hash, UnsignedHead, parse_certification, parse_retirement, service_account_map_key,
};
use serde_json::Value;

/// A service key: the compressed P-256 point.
pub type ServicePublicKey = [u8; 33];

/// The most pages of an account's chain a device reads (a page holds up to 100 entries, so up to
/// 1000 entries; a key's chain is a certification, a few re-signings and a retirement).
pub const MAX_ENTRY_PAGES: usize = 10;

/// What a device pins in its configuration: the log and witness keys and the key service's
/// identity keys, each identity by version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceKeyPins {
    pub log: Pins,
    /// `(version, Ed25519 public key)` of the identities a certification may name.
    pub identity_keys: Vec<(u32, [u8; 32])>,
}

/// What the key service's public API served, as JSON text.
#[derive(Debug, Clone, Copy)]
pub struct LogAnswers<'a> {
    /// `GET /v1/log/lookup/{service_public_key}`.
    pub lookup: &'a str,
    /// `GET /v1/log/entries?service_public_key=`, every page of the chain from the start.
    pub entry_pages: &'a [&'a str],
    /// `GET /v1/log/consistency`, when the log grew since the head this device saw.
    pub consistency: Option<&'a str>,
}

/// A service key the log agrees with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedServiceKey {
    pub identity_version: u32,
    pub public_key: [u8; 33],
    pub statement_hash: [u8; 32],
    /// The certification entry's position in the log.
    pub entry_index: u64,
    /// The head this was checked against; keep it and pass it as `seen` next time.
    pub seen: Seen,
}

/// Why a service key was not accepted. Never carries any bytes it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServiceKeyRefusal {
    /// The head, the proofs or the chain are wrong.
    #[error("the log is wrong: {0}")]
    Log(#[from] log::Refusal),
    /// An answer is not what the public API serves.
    #[error("an answer is malformed")]
    Malformed,
    /// The certification is for another account.
    #[error("the certification is for another account")]
    WrongAccount,
    /// The entries come with different heads, or the head is not the one the lookup named.
    #[error("the answers are not about one head; fetch again")]
    HeadsDiffer,
    /// The log grew since the head this device saw and no matching proof was given.
    #[error("a consistency proof is needed from size {from} to {to}")]
    NeedsConsistency { from: u64, to: u64 },
    /// The chain has an entry that is not a certification for this account and this key.
    #[error("the chain holds a certification for another account or key")]
    ForeignCertification,
    /// A later certification does not name a newer identity than the one before it.
    #[error("a later certification does not name a newer identity")]
    VersionNotNewer,
    /// The chain certifies the key again after retiring it.
    #[error("the key was certified again after it was retired")]
    CertifiedAfterRetirement,
    /// The offered key is not the key this account's devices already verified.
    #[error("the offered key is not the one already verified")]
    KeyChanged,
    /// More entry pages than a chain can need.
    #[error("too many entry pages")]
    TooManyPages,
    /// A witness's time is ahead of this device's clock: the device's clock may be wrong, and the
    /// log is not shown to be.
    #[error("a witness time is ahead of this device's clock")]
    ClockAhead,
    /// The chain holds no certification.
    #[error("the log holds no certification for this key")]
    NotCertified,
    /// The chain ends in a retirement.
    #[error("the key was retired")]
    Retired,
    /// The identity version is not one this device pinned.
    #[error("the identity is not pinned")]
    UnpinnedIdentity,
    /// The pinned identity did not sign the statement.
    #[error("the identity did not sign the certification")]
    BadIdentitySignature,
    /// The certification the record server offered is not the newest one in the log.
    #[error("the offered certification is not the log's newest")]
    OfferedNotNewest,
}

impl ServiceKeyRefusal {
    /// A stable code for a host to branch on (never the message). Each one is one refusal, so a
    /// host can log it, show it or test it without parsing prose.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Log(refusal) => match refusal {
                log::Refusal::UnpinnedLogKey => "unpinned_log_key",
                log::Refusal::TooManyCosignatures => "too_many_cosignatures",
                log::Refusal::BadLogSignature => "bad_log_signature",
                log::Refusal::NotEnoughWitnesses => "not_enough_witnesses",
                log::Refusal::StaleHead => "stale_head",
                log::Refusal::HeadFromTheFuture => "head_from_the_future",
                log::Refusal::Rollback => "log_rollback",
                log::Refusal::Fork => "log_fork",
                log::Refusal::BadConsistency => "bad_consistency",
                log::Refusal::BadMapProof => "bad_map_proof",
                log::Refusal::KeyAbsent => "key_absent",
                log::Refusal::ChainIncomplete => "chain_incomplete",
                log::Refusal::EntryEncoding => "entry_encoding",
                log::Refusal::NotInLog => "not_in_log",
                log::Refusal::WrongChain => "wrong_chain",
                log::Refusal::ChainBroken => "chain_broken",
                log::Refusal::ValueMismatch => "value_mismatch",
            },
            Self::Malformed => "malformed",
            Self::WrongAccount => "wrong_account",
            Self::HeadsDiffer => "heads_differ",
            Self::NeedsConsistency { .. } => "needs_consistency",
            Self::ForeignCertification => "foreign_certification",
            Self::VersionNotNewer => "version_not_newer",
            Self::CertifiedAfterRetirement => "certified_after_retirement",
            Self::KeyChanged => "key_changed",
            Self::TooManyPages => "too_many_pages",
            Self::ClockAhead => "clock_ahead",
            Self::NotCertified => "not_certified",
            Self::Retired => "retired",
            Self::UnpinnedIdentity => "unpinned_identity",
            Self::BadIdentitySignature => "bad_identity_signature",
            Self::OfferedNotNewest => "offered_not_newest",
        }
    }

    /// Whether a host shows a possible-takeover warning: the refusals that say the account's key
    /// or the log is wrong. The others are not verdicts about the account — `ClockAhead` is about
    /// the device's clock, and `Malformed`, `HeadsDiffer`, `NeedsConsistency` and `TooManyPages`
    /// are answers to fetch again — so none of them escrows or warns of a takeover.
    pub fn is_takeover(&self) -> bool {
        !matches!(
            self,
            Self::Malformed
                | Self::HeadsDiffer
                | Self::NeedsConsistency { .. }
                | Self::TooManyPages
                | Self::ClockAhead
        )
    }
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn unhex_vec(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, ServiceKeyRefusal> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ServiceKeyRefusal::Malformed)
}

fn hashes(value: &Value) -> Result<Vec<Hash>, ServiceKeyRefusal> {
    value
        .as_array()
        .ok_or(ServiceKeyRefusal::Malformed)?
        .iter()
        .map(|v| {
            v.as_str()
                .and_then(unhex::<32>)
                .ok_or(ServiceKeyRefusal::Malformed)
        })
        .collect()
}

fn parse(json: &str) -> Result<Value, ServiceKeyRefusal> {
    serde_json::from_str(json).map_err(|_| ServiceKeyRefusal::Malformed)
}

/// The signed head in a lookup or entries answer, and its canonical bytes in hex (to tell that two
/// answers are about the same head).
fn signed_head(body: &Value) -> Result<(SignedHead, String), ServiceKeyRefusal> {
    let head_hex = text(body, "head")?;
    let head = UnsignedHead::decode(&unhex_vec(head_hex).ok_or(ServiceKeyRefusal::Malformed)?)
        .ok_or(ServiceKeyRefusal::Malformed)?;
    let log_signature =
        unhex::<64>(text(body, "log_signature")?).ok_or(ServiceKeyRefusal::Malformed)?;
    let cosignatures = body
        .get("cosignatures")
        .and_then(Value::as_array)
        .ok_or(ServiceKeyRefusal::Malformed)?
        .iter()
        .map(|c| {
            let key = unhex::<32>(text(c, "witness_key")?).ok_or(ServiceKeyRefusal::Malformed)?;
            let bytes = unhex_vec(text(c, "cosignature")?).ok_or(ServiceKeyRefusal::Malformed)?;
            let cosignature = Cosignature::decode(&bytes).ok_or(ServiceKeyRefusal::Malformed)?;
            Ok((key, cosignature))
        })
        .collect::<Result<Vec<_>, ServiceKeyRefusal>>()?;
    Ok((
        SignedHead {
            head,
            log_signature,
            cosignatures,
        },
        head_hex.to_owned(),
    ))
}

fn item(value: &Value) -> Result<ChainItem, ServiceKeyRefusal> {
    Ok(ChainItem {
        index: value
            .get("index")
            .and_then(Value::as_u64)
            .ok_or(ServiceKeyRefusal::Malformed)?,
        chain_index: value
            .get("chain_index")
            .and_then(Value::as_u64)
            .ok_or(ServiceKeyRefusal::Malformed)?,
        entry: unhex_vec(text(value, "entry")?).ok_or(ServiceKeyRefusal::Malformed)?,
        inclusion_proof: hashes(
            value
                .get("inclusion_proof")
                .ok_or(ServiceKeyRefusal::Malformed)?,
        )?,
    })
}

fn b64<const N: usize>(text: &str) -> Result<[u8; N], ServiceKeyRefusal> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or(ServiceKeyRefusal::Malformed)
}

/// Checks the service key the record server offered for the account against the log the key
/// service published. `known_key` is the key this account's devices already verified (see the
/// module doc: `None` is trust on first use). `seen` is the newest head this device verified before (from storage), or
/// `None` the first time; `now_ms` is the device's wall clock.
pub fn verify_service_key(
    pins: &ServiceKeyPins,
    account_id: [u8; 16],
    offered: &wire::ServiceKeyCertification,
    answers: &LogAnswers<'_>,
    known_key: Option<&ServicePublicKey>,
    seen: Option<&Seen>,
    now_ms: u64,
) -> Result<VerifiedServiceKey, ServiceKeyRefusal> {
    // What the record server offered.
    let offered_account =
        crate::trust::uuid_bytes(&offered.account_id).map_err(|_| ServiceKeyRefusal::Malformed)?;
    if offered_account != account_id {
        return Err(ServiceKeyRefusal::WrongAccount);
    }
    let public: ServicePublicKey = b64(&offered.public_key)?;
    if known_key.is_some_and(|known| *known != public) {
        return Err(ServiceKeyRefusal::KeyChanged);
    }
    if answers.entry_pages.len() > MAX_ENTRY_PAGES {
        return Err(ServiceKeyRefusal::TooManyPages);
    }
    let offered_hash: [u8; 32] = b64(&offered.statement_hash)?;
    let offered_signature: [u8; 64] = b64(&offered.signature)?;
    let point = P256Point::parse(&public).map_err(|_| ServiceKeyRefusal::Malformed)?;
    let map_key = service_account_map_key(&public);

    // The head, and the log against the last one this device saw.
    let lookup = parse(answers.lookup)?;
    let (signed, head_hex) = signed_head(&lookup)?;
    let head = log::check_head(&pins.log, &signed, now_ms).map_err(|refusal| match refusal {
        log::Refusal::HeadFromTheFuture => ServiceKeyRefusal::ClockAhead,
        other => ServiceKeyRefusal::Log(other),
    })?;
    let proof = match (seen, answers.consistency) {
        (Some(seen), _) if head.head.size == seen.size => Vec::new(),
        (Some(seen), None) if head.head.size > seen.size => {
            return Err(ServiceKeyRefusal::NeedsConsistency {
                from: seen.size,
                to: head.head.size,
            });
        }
        (Some(seen), Some(json)) if head.head.size > seen.size => {
            let body = parse(json)?;
            let from = body.get("from").and_then(Value::as_u64);
            let to = body.get("to").and_then(Value::as_u64);
            if from != Some(seen.size) || to != Some(head.head.size) {
                return Err(ServiceKeyRefusal::NeedsConsistency {
                    from: seen.size,
                    to: head.head.size,
                });
            }
            hashes(body.get("proof").ok_or(ServiceKeyRefusal::Malformed)?)?
        }
        _ => Vec::new(),
    };
    log::check_progress(seen, &head, &proof)?;
    if unhex::<32>(text(&lookup, "root")?) != Some(head.head.service_map_root) {
        return Err(ServiceKeyRefusal::Log(log::Refusal::BadMapProof));
    }
    let map_proof = unhex_vec(text(&lookup, "proof")?).ok_or(ServiceKeyRefusal::Malformed)?;

    // The account's whole chain, every page about this one head.
    let mut items = Vec::new();
    for page in answers.entry_pages {
        let body = parse(page)?;
        let (_, page_head) = signed_head(&body)?;
        if page_head != head_hex {
            return Err(ServiceKeyRefusal::HeadsDiffer);
        }
        for entry in body
            .get("entries")
            .and_then(Value::as_array)
            .ok_or(ServiceKeyRefusal::Malformed)?
        {
            items.push(item(entry)?);
        }
    }
    let entries = log::check_chain(&head, &map_key, &map_proof, &items)?;

    // What the chain says about the key.
    let mut newest: Option<(usize, u32)> = None;
    let mut retired = false;
    for (position, entry) in entries.iter().enumerate() {
        match entry.kind {
            KIND_SERVICE_KEY => {
                let (statement, _) = parse_certification(&entry.fields)
                    .ok_or(ServiceKeyRefusal::ForeignCertification)?;
                let version = statement
                    .get(8..12)
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map(u32::from_be_bytes)
                    .ok_or(ServiceKeyRefusal::ForeignCertification)?;
                // The statement must be exactly the one for this account, this key and the version
                // it names: another account or another key rebuilds to different bytes.
                if service_key_statement(version, &account_id, &point) != statement {
                    return Err(ServiceKeyRefusal::ForeignCertification);
                }
                // Once retired, a key stays retired: nothing in the chain may certify it again.
                if retired {
                    return Err(ServiceKeyRefusal::CertifiedAfterRetirement);
                }
                // Certifying the same key again is an identity rotation (re-signing under the
                // new version), so the version must rise: an equal one has no honest source.
                if let Some((_, before)) = newest
                    && version <= before
                {
                    return Err(ServiceKeyRefusal::VersionNotNewer);
                }
                newest = Some((position, version));
            }
            KIND_SERVICE_KEY_RETIRE => {
                if parse_retirement(&entry.fields) != Some(public) {
                    return Err(ServiceKeyRefusal::ForeignCertification);
                }
                retired = true;
            }
            _ => {}
        }
    }
    let (position, version) = newest.ok_or(ServiceKeyRefusal::NotCertified)?;
    if retired {
        return Err(ServiceKeyRefusal::Retired);
    }
    let (statement, signature) = parse_certification(&entries[position].fields)
        .ok_or(ServiceKeyRefusal::ForeignCertification)?;
    let (_, identity) = pins
        .identity_keys
        .iter()
        .find(|(v, _)| *v == version)
        .ok_or(ServiceKeyRefusal::UnpinnedIdentity)?;
    orbyn_crypto::verify_service_key_statement(identity, statement, &signature)
        .map_err(|_| ServiceKeyRefusal::BadIdentitySignature)?;

    // It must be the one the record server offered.
    let statement_hash = service_key_statement_hash(statement);
    let entry_index = items[position].index;
    if offered.identity_version != version
        || offered_hash != statement_hash
        || offered_signature != signature
        || offered.entry_index != entry_index
    {
        return Err(ServiceKeyRefusal::OfferedNotNewest);
    }
    Ok(VerifiedServiceKey {
        identity_version: version,
        public_key: public,
        statement_hash,
        entry_index,
        seen: Seen::from(&head),
    })
}

impl crate::Engine {
    /// Checks the account's service key against the log and keeps it on `Ok`. From then on
    /// [`crate::Engine::service_envelopes_for`] seals zone keys to that key and no other; a
    /// refusal leaves the previous key, if any, in place.
    ///
    /// `known_key` and `seen` default to the key and head this engine already holds, so a host that
    /// omits them cannot fall back to trust on first use or to a head older than the one this
    /// engine saw.
    pub fn verify_service_key(
        &mut self,
        pins: &ServiceKeyPins,
        offered: &wire::ServiceKeyCertification,
        answers: &LogAnswers<'_>,
        known_key: Option<&ServicePublicKey>,
        seen: Option<&Seen>,
        now_ms: u64,
    ) -> Result<VerifiedServiceKey, ServiceKeyRefusal> {
        let held = self.service_key.as_ref();
        let known = known_key.or_else(|| held.map(|key| &key.public_key));
        let seen = seen.or_else(|| held.map(|key| &key.seen));
        let verified = verify_service_key(
            pins,
            self.trust.account,
            offered,
            answers,
            known,
            seen,
            now_ms,
        )?;
        self.service_key = Some(verified.clone());
        Ok(verified)
    }

    /// Whether this engine holds a service key that [`crate::Engine::verify_service_key`] accepted.
    pub fn has_verified_service_key(&self) -> bool {
        self.service_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use orbyn_crypto::{P256Keys, service_key_signed_bytes};
    use orbyn_translog::testing::{Log, T0};
    use orbyn_translog::{certification_fields, retirement_fields};
    use serde_json::json;

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const NOW: u64 = T0 + 60_000;

    fn h(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn uuid(bytes: &[u8; 16]) -> String {
        let s = h(bytes);
        format!(
            "{}-{}-{}-{}-{}",
            &s[0..8],
            &s[8..12],
            &s[12..16],
            &s[16..20],
            &s[20..]
        )
    }

    fn identity(version: u8) -> SigningKey {
        SigningKey::from_bytes(&[60 + version; 32])
    }

    /// A certification entry's fields for `account` and `public` under `version`, signed by the
    /// identity of `signer`.
    fn certification(
        version: u32,
        account: &[u8; 16],
        public: &[u8; 33],
        signer: &SigningKey,
    ) -> (Vec<u8>, [u8; 64], Vec<u8>) {
        let point = P256Point::parse(public).expect("a point");
        let statement = service_key_statement(version, account, &point);
        let signature = signer
            .sign(&service_key_signed_bytes(&statement))
            .to_bytes();
        let fields = certification_fields(&statement, &signature).expect("fields");
        (statement, signature, fields)
    }

    struct Case {
        log: Log,
        public: [u8; 33],
        map_key: [u8; 32],
        pins: ServiceKeyPins,
        offered: wire::ServiceKeyCertification,
        signed: orbyn_translog::verify::SignedHead,
        lookup: Value,
        pages: Vec<Value>,
        seen: Option<Seen>,
        consistency: Option<Value>,
        known: Option<ServicePublicKey>,
        now: u64,
    }

    fn head_json(signed: &orbyn_translog::verify::SignedHead) -> Value {
        json!({
            "head": h(&signed.head.encode()),
            "log_signature": h(&signed.log_signature),
            "cosignatures": signed.cosignatures.iter().map(|(k, c)| json!({
                "witness_key": h(k), "cosignature": h(&c.encode()),
            })).collect::<Vec<_>>(),
        })
    }

    impl Case {
        /// Entries before the account's, one certification (version 1), entries after.
        fn new() -> Self {
            Self::with(|log, public, map_key| {
                let (_, _, fields) = certification(1, &ACCOUNT, public, &identity(1));
                log.append(map_key, KIND_SERVICE_KEY, fields, T0 - 10);
            })
        }

        /// A world where `build` writes the account's chain into the log.
        fn with(build: impl FnOnce(&mut Log, &[u8; 33], [u8; 32])) -> Self {
            let public: [u8; 33] = P256Keys::generate()
                .expect("keys")
                .public()
                .compressed()
                .to_owned();
            let map_key = service_account_map_key(&public);
            let mut log = Log::new(3);
            // Another account's entry first, so positions are not the chain's.
            log.append(
                [9; 32],
                KIND_SERVICE_KEY,
                certification_fields(&[0; 77], &[0; 64]).expect("f"),
                T0 - 20,
            );
            build(&mut log, &public, map_key);
            log.append(
                [8; 32],
                KIND_SERVICE_KEY,
                certification_fields(&[0; 77], &[0; 64]).expect("f"),
                T0 - 1,
            );
            let mut case = Self {
                pins: ServiceKeyPins {
                    log: log.pins(2),
                    identity_keys: vec![
                        (1, identity(1).verifying_key().to_bytes()),
                        (2, identity(2).verifying_key().to_bytes()),
                    ],
                },
                signed: log.head(),
                lookup: Value::Null,
                pages: Vec::new(),
                offered: wire::ServiceKeyCertification {
                    account_id: uuid(&ACCOUNT),
                    identity_version: 0,
                    public_key: URL_SAFE_NO_PAD.encode(public),
                    statement_hash: URL_SAFE_NO_PAD.encode([0; 32]),
                    signature: URL_SAFE_NO_PAD.encode([0; 64]),
                    entry_index: 0,
                },
                log,
                public,
                map_key,
                seen: None,
                consistency: None,
                known: None,
                now: NOW,
            };
            case.serve();
            case
        }

        /// Serves the current `signed` head with the log's proofs, and offers the chain's newest
        /// certification (version `version`).
        fn serve(&mut self) {
            let mut lookup = head_json(&self.signed);
            lookup["root"] = json!(h(&self.signed.head.service_map_root));
            lookup["proof"] = json!(h(&self.log.map_proof(&self.map_key)));
            self.lookup = lookup;
            let items = self.log.items(&self.map_key);
            self.pages = items
                .chunks(100)
                .map(|chunk| {
                    let mut page = head_json(&self.signed);
                    page["entries"] = json!(
                        chunk
                            .iter()
                            .map(|i| json!({
                                "index": i.index,
                                "chain_index": i.chain_index,
                                "entry": h(&i.entry),
                                "inclusion_proof": i.inclusion_proof.iter().map(|p| h(p)).collect::<Vec<_>>(),
                            }))
                            .collect::<Vec<_>>()
                    );
                    page
                })
                .collect();
            // Offer the newest certification in the chain.
            for item in items.iter().rev() {
                let entry = orbyn_translog::Entry::decode(&item.entry).expect("entry");
                if entry.kind == KIND_SERVICE_KEY {
                    let (statement, signature) = parse_certification(&entry.fields).expect("cert");
                    let version = u32::from_be_bytes(statement[8..12].try_into().expect("4"));
                    self.offered = wire::ServiceKeyCertification {
                        account_id: uuid(&ACCOUNT),
                        identity_version: version,
                        public_key: URL_SAFE_NO_PAD.encode(self.public),
                        statement_hash: URL_SAFE_NO_PAD
                            .encode(service_key_statement_hash(statement)),
                        signature: URL_SAFE_NO_PAD.encode(signature),
                        entry_index: item.index,
                    };
                    break;
                }
            }
        }

        fn run(&self) -> Result<VerifiedServiceKey, ServiceKeyRefusal> {
            let lookup = self.lookup.to_string();
            let pages: Vec<String> = self.pages.iter().map(Value::to_string).collect();
            let page_refs: Vec<&str> = pages.iter().map(String::as_str).collect();
            let consistency = self.consistency.as_ref().map(Value::to_string);
            verify_service_key(
                &self.pins,
                ACCOUNT,
                &self.offered,
                &LogAnswers {
                    lookup: &lookup,
                    entry_pages: &page_refs,
                    consistency: consistency.as_deref(),
                },
                self.known.as_ref(),
                self.seen.as_ref(),
                self.now,
            )
        }
    }

    #[test]
    fn a_refusal_names_a_stable_code_and_whether_it_warns_of_a_takeover() {
        assert_eq!(ServiceKeyRefusal::KeyChanged.code(), "key_changed");
        assert!(ServiceKeyRefusal::KeyChanged.is_takeover());
        assert_eq!(
            ServiceKeyRefusal::Log(log::Refusal::Fork).code(),
            "log_fork"
        );
        assert!(ServiceKeyRefusal::Log(log::Refusal::Fork).is_takeover());
        // Not verdicts about the account: the device's clock, or answers to fetch again.
        assert_eq!(ServiceKeyRefusal::ClockAhead.code(), "clock_ahead");
        assert!(!ServiceKeyRefusal::ClockAhead.is_takeover());
        assert!(!ServiceKeyRefusal::NeedsConsistency { from: 1, to: 2 }.is_takeover());
        assert!(!ServiceKeyRefusal::HeadsDiffer.is_takeover());
        assert!(!ServiceKeyRefusal::Malformed.is_takeover());
        assert!(!ServiceKeyRefusal::TooManyPages.is_takeover());
    }

    #[test]
    fn a_certified_key_the_log_agrees_with_is_accepted() {
        let case = Case::new();
        let key = case.run().expect("accepted");
        assert_eq!(key.identity_version, 1);
        assert_eq!(key.public_key, case.public);
        assert_eq!(key.seen.size, case.signed.head.size);
        assert_eq!(key.entry_index, case.offered.entry_index);
    }

    #[test]
    fn a_recertification_under_a_newer_identity_is_accepted_when_it_is_the_one_offered() {
        let mut case = Case::with(|log, public, map_key| {
            let (_, _, f1) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f1, T0 - 10);
            let (_, _, f2) = certification(2, &ACCOUNT, public, &identity(2));
            log.append(map_key, KIND_SERVICE_KEY, f2, T0 - 5);
        });
        assert_eq!(case.run().expect("accepted").identity_version, 2);
        // The server still offering the first one is stale, not the log's newest.
        let (statement, signature, _) = certification(1, &ACCOUNT, &case.public, &identity(1));
        case.offered.identity_version = 1;
        case.offered.statement_hash =
            URL_SAFE_NO_PAD.encode(service_key_statement_hash(&statement));
        case.offered.signature = URL_SAFE_NO_PAD.encode(signature);
        assert_eq!(case.run(), Err(ServiceKeyRefusal::OfferedNotNewest));
    }

    #[test]
    fn what_the_record_server_offered_must_be_the_logs() {
        let base = Case::new();
        let mut c = Case::new();
        c.offered.account_id = uuid(&[0xB2; 16]);
        assert_eq!(c.run(), Err(ServiceKeyRefusal::WrongAccount));
        for (name, tamper) in [
            ("version", 0),
            ("hash", 1),
            ("signature", 2),
            ("entry index", 3),
        ] {
            let mut c = Case::new();
            c.pins = base.pins.clone();
            match tamper {
                0 => c.offered.identity_version += 1,
                1 => {
                    let mut hash = URL_SAFE_NO_PAD
                        .decode(&c.offered.statement_hash)
                        .expect("b64");
                    hash[0] ^= 1;
                    c.offered.statement_hash = URL_SAFE_NO_PAD.encode(hash);
                }
                2 => {
                    let mut sig = URL_SAFE_NO_PAD.decode(&c.offered.signature).expect("b64");
                    sig[0] ^= 1;
                    c.offered.signature = URL_SAFE_NO_PAD.encode(sig);
                }
                _ => c.offered.entry_index += 1,
            }
            assert_eq!(c.run(), Err(ServiceKeyRefusal::OfferedNotNewest), "{name}");
        }
        // Not base64, wrong lengths and a key that is not a point.
        for field in 0..3 {
            let mut c = Case::new();
            match field {
                0 => c.offered.public_key = "!!".into(),
                1 => c.offered.statement_hash = URL_SAFE_NO_PAD.encode([1; 31]),
                _ => c.offered.signature = URL_SAFE_NO_PAD.encode([1; 65]),
            }
            assert_eq!(c.run(), Err(ServiceKeyRefusal::Malformed));
        }
        let mut c = Case::new();
        c.offered.public_key = URL_SAFE_NO_PAD.encode([5; 33]);
        assert_eq!(c.run(), Err(ServiceKeyRefusal::Malformed));
        let mut c = Case::new();
        c.offered.account_id = "not a uuid".into();
        assert_eq!(c.run(), Err(ServiceKeyRefusal::Malformed));
    }

    #[test]
    fn the_identity_must_be_pinned_and_must_have_signed() {
        let mut c = Case::new();
        c.pins.identity_keys = vec![(2, identity(2).verifying_key().to_bytes())];
        assert_eq!(c.run(), Err(ServiceKeyRefusal::UnpinnedIdentity));
        let mut c = Case::new();
        c.pins.identity_keys = vec![(1, identity(2).verifying_key().to_bytes())];
        assert_eq!(c.run(), Err(ServiceKeyRefusal::BadIdentitySignature));
        // Signed by another identity in the log itself, though the version says 1.
        let mut c = Case::with(|log, public, map_key| {
            let (_, _, fields) = certification(1, &ACCOUNT, public, &identity(2));
            log.append(map_key, KIND_SERVICE_KEY, fields, T0 - 10);
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::BadIdentitySignature));
        c.pins.identity_keys = vec![(1, identity(2).verifying_key().to_bytes())];
        assert!(
            c.run().is_ok(),
            "the same log is fine for a device that pins that identity"
        );
    }

    #[test]
    fn a_chain_with_another_account_another_key_or_no_certification_is_refused() {
        // A certification for another account, filed under this key.
        let c = Case::with(|log, public, map_key| {
            let (_, _, fields) = certification(1, &[0xB2; 16], public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, fields, T0 - 10);
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::ForeignCertification));
        // A second, different key certified in the same chain.
        let c = Case::with(|log, public, map_key| {
            let (_, _, f1) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f1, T0 - 10);
            let other = P256Keys::generate()
                .expect("k")
                .public()
                .compressed()
                .to_owned();
            let (_, _, f2) = certification(1, &ACCOUNT, &other, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f2, T0 - 5);
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::ForeignCertification));
        // A statement whose bytes are not the canonical rebuild.
        let c = Case::with(|log, _, map_key| {
            log.append(
                map_key,
                KIND_SERVICE_KEY,
                certification_fields(&[3; 77], &[3; 64]).expect("f"),
                T0 - 10,
            );
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::ForeignCertification));
        // A chain without any certification (a rotation entry only).
        let c = Case::with(|log, _, map_key| {
            log.append(
                map_key,
                orbyn_translog::KIND_ROTATION,
                vec![1, 2, 3],
                T0 - 10,
            );
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::NotCertified));
        // A later certification naming an older identity.
        let c = Case::with(|log, public, map_key| {
            let (_, _, f2) = certification(2, &ACCOUNT, public, &identity(2));
            log.append(map_key, KIND_SERVICE_KEY, f2, T0 - 10);
            let (_, _, f1) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f1, T0 - 5);
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::VersionNotNewer));
    }

    #[test]
    fn a_retired_key_is_refused_and_a_retirement_of_another_key_is_foreign() {
        let c = Case::with(|log, public, map_key| {
            let (_, _, fields) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, fields, T0 - 10);
            log.append(
                map_key,
                KIND_SERVICE_KEY_RETIRE,
                retirement_fields(public),
                T0 - 5,
            );
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::Retired));
        let c = Case::with(|log, public, map_key| {
            let (_, _, fields) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, fields, T0 - 10);
            log.append(
                map_key,
                KIND_SERVICE_KEY_RETIRE,
                retirement_fields(&[2; 33]),
                T0 - 5,
            );
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::ForeignCertification));
    }

    #[test]
    fn a_second_key_certified_for_the_account_is_refused_once_a_key_is_known() {
        // Two keys, each with its own valid chain for the same account.
        let first = Case::new();
        let second = Case::new();
        assert_ne!(first.public, second.public);
        // Trust on first use: with nothing known, each verifies alone.
        first.run().expect("the first key");
        second.run().expect("the second key, on its own");
        // Once the first is known, the second is refused, and the first still passes.
        let mut c = Case::new();
        c.known = Some(first.public);
        assert_eq!(c.run(), Err(ServiceKeyRefusal::KeyChanged));
        let mut c = Case::new();
        c.known = Some(c.public);
        c.run().expect("the known key");
    }

    #[test]
    fn the_same_key_certified_again_under_a_newer_identity_is_accepted_and_an_equal_one_is_not() {
        let c = Case::with(|log, public, map_key| {
            let (_, _, f1) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f1, T0 - 10);
            let (_, _, f2) = certification(2, &ACCOUNT, public, &identity(2));
            log.append(map_key, KIND_SERVICE_KEY, f2, T0 - 5);
        });
        assert_eq!(c.run().expect("rotated").identity_version, 2);
        let c = Case::with(|log, public, map_key| {
            for at in [T0 - 10, T0 - 5] {
                let (_, _, f) = certification(1, &ACCOUNT, public, &identity(1));
                log.append(map_key, KIND_SERVICE_KEY, f, at);
            }
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::VersionNotNewer));
    }

    #[test]
    fn a_certification_after_a_retirement_is_refused() {
        let c = Case::with(|log, public, map_key| {
            let (_, _, f1) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f1, T0 - 10);
            log.append(
                map_key,
                KIND_SERVICE_KEY_RETIRE,
                retirement_fields(public),
                T0 - 7,
            );
            let (_, _, f2) = certification(2, &ACCOUNT, public, &identity(2));
            log.append(map_key, KIND_SERVICE_KEY, f2, T0 - 5);
        });
        assert_eq!(c.run(), Err(ServiceKeyRefusal::CertifiedAfterRetirement));
    }

    #[test]
    fn too_many_pages_and_a_clock_behind_the_witnesses_are_their_own_verdicts() {
        let mut c = Case::new();
        let page = c.pages[0].clone();
        c.pages = vec![page; MAX_ENTRY_PAGES + 1];
        assert_eq!(c.run(), Err(ServiceKeyRefusal::TooManyPages));
        // The device's clock is more than five minutes behind the witnesses' time.
        let mut c = Case::new();
        c.now = T0 - 6 * 60 * 1000;
        assert_eq!(c.run(), Err(ServiceKeyRefusal::ClockAhead));
    }

    #[test]
    fn a_log_that_is_wrong_is_refused_in_each_way() {
        // Too few witnesses.
        let mut c = Case::new();
        c.signed = c.log.head_at(T0, &[0]);
        c.serve();
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::NotEnoughWitnesses))
        );
        // Stale.
        let mut c = Case::new();
        c.now = T0 + log::MAX_HEAD_AGE_MS + 1;
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::StaleHead))
        );
        // The key is absent from a map that is otherwise fine: a valid absence proof is a refusal.
        let c = Case::with(|_, _, _| {});
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::KeyAbsent))
        );
        // The lookup's root is not the head's.
        let mut c = Case::new();
        c.lookup["root"] = json!(h(&[7; 32]));
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::BadMapProof))
        );
        // The newest entry left out of the pages.
        let mut c = Case::new();
        let mut c2 = Case::with(|log, public, map_key| {
            let (_, _, f1) = certification(1, &ACCOUNT, public, &identity(1));
            log.append(map_key, KIND_SERVICE_KEY, f1, T0 - 10);
            let (_, _, f2) = certification(2, &ACCOUNT, public, &identity(2));
            log.append(map_key, KIND_SERVICE_KEY, f2, T0 - 5);
        });
        c2.pages[0]["entries"]
            .as_array_mut()
            .expect("entries")
            .pop();
        assert_eq!(
            c2.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::ValueMismatch))
        );
        // An entry that is not in the log of this head.
        c.pages[0]["entries"][0]["inclusion_proof"][0] = json!(h(&[1; 32]));
        assert_eq!(c.run(), Err(ServiceKeyRefusal::Log(log::Refusal::NotInLog)));
    }

    #[test]
    fn pages_of_another_head_and_malformed_answers_are_refused() {
        let mut c = Case::new();
        let mut later = c.log.clone();
        later.append(
            [5; 32],
            KIND_SERVICE_KEY,
            certification_fields(&[0; 77], &[0; 64]).expect("f"),
            T0,
        );
        let other = later.head();
        c.pages[0]["head"] = head_json(&other)["head"].clone();
        assert_eq!(c.run(), Err(ServiceKeyRefusal::HeadsDiffer));
        for tamper in 0..6 {
            let mut c = Case::new();
            match tamper {
                0 => c.lookup["head"] = json!("zz"),
                1 => c.lookup["log_signature"] = json!(h(&[1; 63])),
                2 => c.lookup["cosignatures"] = json!("none"),
                3 => c.lookup["proof"] = json!(7),
                4 => c.pages[0]["entries"][0]["index"] = json!("one"),
                _ => c.pages[0]["entries"] = json!(null),
            }
            assert_eq!(c.run(), Err(ServiceKeyRefusal::Malformed), "{tamper}");
        }
        let c = Case::new();
        assert_eq!(
            verify_service_key(
                &c.pins,
                ACCOUNT,
                &c.offered,
                &LogAnswers {
                    lookup: "{",
                    entry_pages: &[],
                    consistency: None
                },
                None,
                None,
                NOW,
            ),
            Err(ServiceKeyRefusal::Malformed)
        );
    }

    #[test]
    fn a_head_is_checked_against_the_last_one_seen() {
        let mut c = Case::new();
        let first = c.run().expect("accepted").seen;
        // The log grows; the device saw the earlier head.
        let old_size = c.log.size();
        c.log.append(
            [6; 32],
            KIND_SERVICE_KEY,
            certification_fields(&[0; 77], &[0; 64]).expect("f"),
            T0,
        );
        c.signed = c.log.head_at(T0 + 1000, &[0, 1, 2]);
        c.serve();
        c.seen = Some(first);
        // No proof: ask for one.
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::NeedsConsistency {
                from: old_size,
                to: old_size + 1
            })
        );
        // A proof for other sizes: ask again.
        c.consistency = Some(json!({"from": 1, "to": old_size + 1, "proof": []}));
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::NeedsConsistency {
                from: old_size,
                to: old_size + 1
            })
        );
        // A wrong proof.
        c.consistency = Some(json!({"from": old_size, "to": old_size + 1, "proof": [h(&[1; 32])]}));
        assert_eq!(
            c.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::BadConsistency))
        );
        // The right one.
        let proof: Vec<String> = c.log.consistency(old_size).iter().map(|p| h(p)).collect();
        c.consistency = Some(json!({"from": old_size, "to": old_size + 1, "proof": proof}));
        assert!(c.run().is_ok());
        // A log that shrank, and one that forked at the same size.
        let mut shrunk = Case::new();
        shrunk.seen = Some(Seen {
            size: 99,
            ..Seen::from(&log::check_head(&shrunk.pins.log, &shrunk.signed, NOW).expect("head"))
        });
        assert_eq!(
            shrunk.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::Rollback))
        );
        let mut forked = Case::new();
        let mut seen =
            Seen::from(&log::check_head(&forked.pins.log, &forked.signed, NOW).expect("head"));
        seen.log_root[0] ^= 1;
        forked.seen = Some(seen);
        assert_eq!(
            forked.run(),
            Err(ServiceKeyRefusal::Log(log::Refusal::Fork))
        );
    }
}
