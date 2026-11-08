//! What a device checks about the log before it relies on anything in it: pure code over bytes
//! already fetched, with no IO, no clock of its own and no JSON, so it runs natively and in
//! WebAssembly and a host decides what to fetch and when.
//!
//! Three steps, each refusing with a named [`Refusal`]:
//!
//! 1. [`check_head`]: the log key (pinned, by version) signed the head, enough distinct pinned
//!    witnesses cosigned it, and it is fresh by the **witnesses' signed time**, never the head's
//!    own `time_ms` (a key service whose clock is wrong or malicious cannot make an old head look
//!    new).
//! 2. [`check_progress`]: against the last head this device saw, the log has not shrunk, an
//!    equal size has equal roots, and a larger one is consistent with it (RFC 9162).
//! 3. [`check_chain`]: an account's service-map proof shows the key **present** under the head's
//!    map root, and its chain of entries is whole: each in the log of that head, filed under the
//!    account's map key, linked to the one before, and ending at the entry the map's value names,
//!    so an omitted newest entry shows as a value that does not match.
//!
//! A fetch that fails or a service that has published nothing is availability: the host never
//! calls these and never reports a takeover. Everything here that fails is a verdict on bytes.

use crate::cosign::{Cosignature, cosigned_enough};
use crate::entry::{Entry, MapId, map_value};
use crate::head::UnsignedHead;
use crate::map::{self, Lookup, Proof};
use crate::merkle::{Hash, leaf_hash, verify_consistency, verify_inclusion};

/// How old the newest witness time behind a head may be: two hours.
pub const MAX_HEAD_AGE_MS: u64 = 2 * 60 * 60 * 1000;
/// How far ahead of the device's clock a witness time may be: five minutes.
pub const MAX_CLOCK_AHEAD_MS: u64 = 5 * 60 * 1000;

/// Why bytes from the log were refused. Never carries any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the head names a log key version this device has not pinned")]
    UnpinnedLogKey,
    #[error("the log key did not sign the head")]
    BadLogSignature,
    #[error("too few pinned witnesses cosigned the head (or the pinned set is not usable)")]
    NotEnoughWitnesses,
    #[error("the newest witness time behind the head is too old")]
    StaleHead,
    #[error("a witness time is ahead of this device's clock")]
    HeadFromTheFuture,
    #[error("the log is smaller, or its witnessed time older, than a head already seen")]
    Rollback,
    #[error("two different logs have the same size")]
    Fork,
    #[error("the consistency proof does not connect the heads")]
    BadConsistency,
    #[error("the map proof does not match the head's map root")]
    BadMapProof,
    #[error("the map shows no entry for this key")]
    KeyAbsent,
    #[error("the chain has no entries, or its entries are not numbered from zero without gaps")]
    ChainIncomplete,
    #[error("an entry is not in the canonical encoding")]
    EntryEncoding,
    #[error("an entry is not in the log of this head")]
    NotInLog,
    #[error("an entry is filed in another map or under another account")]
    WrongChain,
    #[error("the entries do not link to one another")]
    ChainBroken,
    #[error("the newest entry is not the one the map holds")]
    ValueMismatch,
}

/// The keys a device pins in its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pins {
    /// `(version, public key)` of the log keys in use.
    pub log_keys: Vec<(u32, [u8; 32])>,
    pub witnesses: Vec<[u8; 32]>,
    /// More than half of `witnesses` (see [`crate::threshold_ok`]).
    pub threshold: usize,
}

/// A head as served: its fields, the log key's signature, and the cosignatures with the witness
/// key each claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    pub head: UnsignedHead,
    pub log_signature: [u8; 64],
    pub cosignatures: Vec<([u8; 32], Cosignature)>,
}

/// A head that passed [`check_head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedHead {
    pub head: UnsignedHead,
    pub hash: Hash,
    /// The witness time behind the head: the `threshold`-th newest time among the distinct pinned
    /// witnesses that cosigned it, so one witness cannot make a head look fresh alone.
    pub witnessed_ms: u64,
}

/// What a device keeps of the newest head it verified, to check the next one against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub size: u64,
    pub log_root: Hash,
    pub service_map_root: Hash,
    pub identity_map_root: Hash,
    pub witnessed_ms: u64,
}

impl From<&CheckedHead> for Seen {
    fn from(h: &CheckedHead) -> Self {
        Self {
            size: h.head.size,
            log_root: h.head.log_root,
            service_map_root: h.head.service_map_root,
            identity_map_root: h.head.identity_map_root,
            witnessed_ms: h.witnessed_ms,
        }
    }
}

/// Checks the log key's signature, the witnesses' cosignatures and the head's freshness at
/// `now_ms` (the device's clock).
pub fn check_head(pins: &Pins, signed: &SignedHead, now_ms: u64) -> Result<CheckedHead, Refusal> {
    let head = &signed.head;
    let (_, log_key) = pins
        .log_keys
        .iter()
        .find(|(version, _)| *version == head.log_key_version)
        .ok_or(Refusal::UnpinnedLogKey)?;
    if !head.verify(log_key, &signed.log_signature) {
        return Err(Refusal::BadLogSignature);
    }
    let hash = head.hash();
    let served: Vec<Cosignature> = signed
        .cosignatures
        .iter()
        .filter(|(key, cosignature)| pins.witnesses.contains(key) && cosignature.verify(key))
        .map(|(_, cosignature)| cosignature.clone())
        .collect();
    if !cosigned_enough(&hash, &pins.witnesses, &served, pins.threshold) {
        return Err(Refusal::NotEnoughWitnesses);
    }
    // One time per distinct pinned witness that signed this very head (the newest it signed).
    let mut times: Vec<u64> = pins
        .witnesses
        .iter()
        .filter_map(|witness| {
            signed
                .cosignatures
                .iter()
                .filter(|(key, c)| key == witness && c.head_hash == hash && c.verify(witness))
                .map(|(_, c)| c.time_ms)
                .max()
        })
        .collect();
    times.sort_unstable_by(|a, b| b.cmp(a));
    let witnessed_ms = *times
        .get(pins.threshold.saturating_sub(1))
        .ok_or(Refusal::NotEnoughWitnesses)?;
    if witnessed_ms > now_ms.saturating_add(MAX_CLOCK_AHEAD_MS) {
        return Err(Refusal::HeadFromTheFuture);
    }
    if now_ms.saturating_sub(witnessed_ms) > MAX_HEAD_AGE_MS {
        return Err(Refusal::StaleHead);
    }
    Ok(CheckedHead {
        head: head.clone(),
        hash,
        witnessed_ms,
    })
}

/// Checks `new` against the newest head this device saw. `consistency` is the RFC 9162 proof from
/// the old size to the new one; it is only read when the log grew.
pub fn check_progress(
    seen: Option<&Seen>,
    new: &CheckedHead,
    consistency: &[Hash],
) -> Result<(), Refusal> {
    let Some(seen) = seen else {
        return Ok(());
    };
    let head = &new.head;
    if head.size < seen.size || new.witnessed_ms < seen.witnessed_ms {
        return Err(Refusal::Rollback);
    }
    if head.size == seen.size {
        let same = head.log_root == seen.log_root
            && head.service_map_root == seen.service_map_root
            && head.identity_map_root == seen.identity_map_root;
        return if same { Ok(()) } else { Err(Refusal::Fork) };
    }
    verify_consistency(
        seen.size,
        head.size,
        &seen.log_root,
        &head.log_root,
        consistency,
    )
    .map_err(|_| Refusal::BadConsistency)
}

/// One entry of an account's chain as served: its position in the log and in the chain, its
/// canonical bytes and its inclusion proof against the head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainItem {
    pub index: u64,
    pub chain_index: u64,
    pub entry: Vec<u8>,
    pub inclusion_proof: Vec<Hash>,
}

/// Checks the service map's proof for `map_key` against the head and the whole chain behind it,
/// and returns the chain's entries oldest first. `items` must be every entry of the chain, from
/// chain index 0, each served against **this** head.
pub fn check_chain(
    head: &CheckedHead,
    map_key: &[u8; 32],
    map_proof: &[u8],
    items: &[ChainItem],
) -> Result<Vec<Entry>, Refusal> {
    let proof = Proof::decode(map_proof).map_err(|_| Refusal::BadMapProof)?;
    let value = match map::verify(&head.head.service_map_root, map_key, &proof)
        .map_err(|_| Refusal::BadMapProof)?
    {
        Lookup::Present(value) => value,
        Lookup::Absent => return Err(Refusal::KeyAbsent),
    };
    if items.is_empty() {
        return Err(Refusal::ChainIncomplete);
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(items.len());
    let mut previous: Option<(Hash, u64)> = None;
    for (position, item) in items.iter().enumerate() {
        if item.chain_index != position as u64 {
            return Err(Refusal::ChainIncomplete);
        }
        let entry = Entry::decode(&item.entry).map_err(|_| Refusal::EntryEncoding)?;
        let hash = leaf_hash(&item.entry);
        if entry.hash().map_err(|_| Refusal::EntryEncoding)? != hash {
            return Err(Refusal::EntryEncoding);
        }
        verify_inclusion(
            &hash,
            item.index,
            head.head.size,
            &item.inclusion_proof,
            &head.head.log_root,
        )
        .map_err(|_| Refusal::NotInLog)?;
        if entry.map != MapId::Service || &entry.map_key != map_key {
            return Err(Refusal::WrongChain);
        }
        match previous {
            None if entry.prev != [0u8; 32] => return Err(Refusal::ChainBroken),
            Some((prev_hash, prev_index))
                if entry.prev != prev_hash || item.index <= prev_index =>
            {
                return Err(Refusal::ChainBroken);
            }
            _ => {}
        }
        previous = Some((hash, item.index));
        entries.push(entry);
    }
    let (last_hash, _) = previous.ok_or(Refusal::ChainIncomplete)?;
    if map_value(&last_hash, items.len() as u64) != value {
        return Err(Refusal::ValueMismatch);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosign::cosign_message;
    use crate::entry::{KIND_SERVICE_KEY, certification_fields, service_account_map_key};
    use crate::testing::{Log, T0};
    use ed25519_dalek::Signer;

    const KEY: [u8; 32] = [7; 32];
    const NOW: u64 = T0 + 60_000;

    fn fields() -> Vec<u8> {
        certification_fields(&[1; 77], &[2; 64]).expect("ok")
    }

    /// Three witnesses (threshold 2), a few entries of other accounts and a chain of two for KEY.
    fn log() -> Log {
        let mut log = Log::new(3);
        log.append([1; 32], KIND_SERVICE_KEY, fields(), T0 - 5);
        log.append(KEY, KIND_SERVICE_KEY, fields(), T0 - 4);
        log.append([2; 32], KIND_SERVICE_KEY, fields(), T0 - 3);
        log.append(KEY, KIND_SERVICE_KEY, fields(), T0 - 2);
        log.append([3; 32], KIND_SERVICE_KEY, fields(), T0 - 1);
        log
    }

    fn checked(log: &mut Log) -> CheckedHead {
        check_head(&log.pins(2), &log.head(), NOW).expect("ok")
    }

    #[test]
    fn the_limits_are_the_documented_ones() {
        assert_eq!(MAX_HEAD_AGE_MS, 7_200_000, "two hours");
        assert_eq!(MAX_CLOCK_AHEAD_MS, 300_000, "five minutes");
    }

    #[test]
    fn a_good_head_and_chain_pass() {
        let mut log = log();
        let head = checked(&mut log);
        assert_eq!(head.witnessed_ms, T0);
        let entries = check_chain(&head, &KEY, &log.map_proof(&KEY), &log.items(&KEY)).expect("ok");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prev, [0; 32]);
        assert_eq!(entries[1].prev, entries[0].hash().expect("ok"));
    }

    #[test]
    fn a_log_key_that_is_not_pinned_or_did_not_sign_is_refused() {
        let mut log = log();
        let signed = log.head();
        let mut pins = log.pins(2);
        pins.log_keys = vec![(2, pins.log_keys[0].1)];
        assert_eq!(
            check_head(&pins, &signed, NOW),
            Err(Refusal::UnpinnedLogKey)
        );
        let mut pins = log.pins(2);
        pins.log_keys[0].1 = [9; 32];
        assert_eq!(
            check_head(&pins, &signed, NOW),
            Err(Refusal::BadLogSignature)
        );
        let mut forged = signed.clone();
        forged.log_signature[0] ^= 1;
        assert_eq!(
            check_head(&log.pins(2), &forged, NOW),
            Err(Refusal::BadLogSignature)
        );
        let mut changed = signed;
        changed.head.size += 1;
        assert_eq!(
            check_head(&log.pins(2), &changed, NOW),
            Err(Refusal::BadLogSignature)
        );
    }

    #[test]
    fn too_few_pinned_witnesses_is_refused_whatever_else_is_served() {
        let mut log = log();
        let pins = log.pins(2);
        // One witness of three.
        let one = log.head_at(T0, &[0]);
        assert_eq!(
            check_head(&pins, &one, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        // The same witness twice still counts once.
        let mut twice = one.clone();
        twice.cosignatures.push(twice.cosignatures[0].clone());
        assert_eq!(
            check_head(&pins, &twice, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        // A witness that is not pinned does not count.
        let mut stranger = log.head_at(T0, &[0]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[200; 32]);
        let signature = other
            .sign(&cosign_message(&stranger.head.hash(), T0))
            .to_bytes();
        stranger.cosignatures.push((
            other.verifying_key().to_bytes(),
            Cosignature {
                head_hash: stranger.head.hash(),
                time_ms: T0,
                signature,
            },
        ));
        assert_eq!(
            check_head(&pins, &stranger, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        // A cosignature of another head does not count.
        let mut other_head = log.head_at(T0, &[0, 1]);
        other_head.cosignatures[1].1.head_hash = [3; 32];
        assert_eq!(
            check_head(&pins, &other_head, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        // A cosignature claimed under another witness's key does not count.
        let mut swapped = log.head_at(T0, &[0, 1]);
        swapped.cosignatures[1].0 = swapped.cosignatures[0].0;
        assert_eq!(
            check_head(&pins, &swapped, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        // A pinned set that is not usable (threshold not above half) never passes.
        let all = log.head_at(T0, &[0, 1, 2]);
        assert_eq!(
            check_head(&log.pins(1), &all, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        assert_eq!(
            check_head(&log.pins(0), &all, NOW),
            Err(Refusal::NotEnoughWitnesses)
        );
        assert!(check_head(&pins, &all, NOW).is_ok());
    }

    #[test]
    fn freshness_is_the_witnesses_time_not_the_heads_and_one_witness_cannot_set_it() {
        let mut log = log();
        let pins = log.pins(2);
        let signed = log.head_at(T0, &[0, 1, 2]);
        // Exactly two hours is still fresh; a millisecond more is stale.
        assert!(check_head(&pins, &signed, T0 + MAX_HEAD_AGE_MS).is_ok());
        assert_eq!(
            check_head(&pins, &signed, T0 + MAX_HEAD_AGE_MS + 1),
            Err(Refusal::StaleHead)
        );
        // The head's own time says it is new; the witnesses' time says it is old.
        let mut head = signed.head.clone();
        head.time_ms = T0 + 10 * MAX_HEAD_AGE_MS;
        let relabelled = log.sign(head, T0, &[0, 1, 2]);
        assert_eq!(
            check_head(&pins, &relabelled, T0 + 10 * MAX_HEAD_AGE_MS),
            Err(Refusal::StaleHead)
        );
        // Two witnesses are stale, one is fresh: the threshold-th newest decides.
        let head = signed.head.clone();
        let mut mixed = log.sign(head.clone(), T0, &[0, 1]);
        let fresh = log.sign(head, T0 + 3 * MAX_HEAD_AGE_MS, &[2]);
        mixed.cosignatures.extend(fresh.cosignatures);
        assert_eq!(
            check_head(&pins, &mixed, T0 + 3 * MAX_HEAD_AGE_MS),
            Err(Refusal::StaleHead)
        );
        // A witness time ahead of the device's clock is refused.
        let ahead = log.sign(signed.head.clone(), T0 + MAX_CLOCK_AHEAD_MS + 1, &[0, 1, 2]);
        assert_eq!(
            check_head(&pins, &ahead, T0),
            Err(Refusal::HeadFromTheFuture)
        );
        let near = log.sign(signed.head, T0 + MAX_CLOCK_AHEAD_MS, &[0, 1, 2]);
        assert!(check_head(&pins, &near, T0).is_ok());
    }

    #[test]
    fn progress_refuses_a_smaller_log_an_older_time_a_fork_and_a_bad_proof() {
        let mut log = log();
        let first = checked(&mut log);
        let seen = Seen::from(&first);
        let old_size = log.size();
        // The same head again, and an idle head of the same size and roots.
        assert_eq!(check_progress(Some(&seen), &first, &[]), Ok(()));
        assert_eq!(check_progress(None, &first, &[]), Ok(()));
        // A larger log with the right proof.
        log.append([4; 32], KIND_SERVICE_KEY, fields(), T0);
        let pins = log.pins(2);
        let later = check_head(&pins, &log.head_at(T0 + 1000, &[0, 1, 2]), NOW).expect("ok");
        let proof = log.consistency(old_size);
        assert_eq!(check_progress(Some(&seen), &later, &proof), Ok(()));
        // Wrong, missing and extra proof hashes.
        assert_eq!(
            check_progress(Some(&seen), &later, &[]),
            Err(Refusal::BadConsistency)
        );
        let mut bad = proof.clone();
        bad[0][0] ^= 1;
        assert_eq!(
            check_progress(Some(&seen), &later, &bad),
            Err(Refusal::BadConsistency)
        );
        let mut extra = proof;
        extra.push([0; 32]);
        assert_eq!(
            check_progress(Some(&seen), &later, &extra),
            Err(Refusal::BadConsistency)
        );
        // The log went back: the earlier head against a seen later one.
        let seen_later = Seen::from(&later);
        assert_eq!(
            check_progress(Some(&seen_later), &first, &[]),
            Err(Refusal::Rollback)
        );
        // Same size, older witness time.
        let mut older = first.clone();
        older.witnessed_ms = seen.witnessed_ms - 1;
        assert_eq!(
            check_progress(Some(&seen), &older, &[]),
            Err(Refusal::Rollback)
        );
        // Same size with different roots: a fork, in each of the three roots.
        for tamper in 0..3 {
            let mut forked = first.clone();
            match tamper {
                0 => forked.head.log_root[0] ^= 1,
                1 => forked.head.service_map_root[0] ^= 1,
                _ => forked.head.identity_map_root[0] ^= 1,
            }
            assert_eq!(
                check_progress(Some(&seen), &forked, &[]),
                Err(Refusal::Fork)
            );
        }
    }

    #[test]
    fn a_map_proof_must_match_the_head_and_show_the_key() {
        let mut log = log();
        let head = checked(&mut log);
        let items = log.items(&KEY);
        // A proof for another key is a proof of that key: the walk for KEY ends elsewhere.
        let other = log.map_proof(&[1; 32]);
        assert!(matches!(
            check_chain(&head, &KEY, &other, &items),
            Err(Refusal::BadMapProof | Refusal::KeyAbsent)
        ));
        // Garbage and a flipped byte.
        assert_eq!(
            check_chain(&head, &KEY, &[1, 2, 3], &items),
            Err(Refusal::BadMapProof)
        );
        let mut flipped = log.map_proof(&KEY);
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            check_chain(&head, &KEY, &flipped, &items),
            Err(Refusal::BadMapProof)
        );
        // A proof against a map root the head does not carry.
        let mut other_head = head.clone();
        other_head.head.service_map_root[0] ^= 1;
        assert_eq!(
            check_chain(&other_head, &KEY, &log.map_proof(&KEY), &items),
            Err(Refusal::BadMapProof)
        );
        // An account the map does not hold: a valid absence proof is still a refusal.
        let unknown = service_account_map_key(&[2; 33]);
        assert_eq!(
            check_chain(&head, &unknown, &log.map_proof(&unknown), &[]),
            Err(Refusal::KeyAbsent)
        );
    }

    #[test]
    fn a_chain_with_a_gap_an_omission_or_a_foreign_entry_is_refused() {
        let mut log = log();
        let head = checked(&mut log);
        let proof = log.map_proof(&KEY);
        let items = log.items(&KEY);
        assert_eq!(
            check_chain(&head, &KEY, &proof, &[]),
            Err(Refusal::ChainIncomplete)
        );
        // The newest entry left out: the map's value names it.
        assert_eq!(
            check_chain(&head, &KEY, &proof, &items[..1]),
            Err(Refusal::ValueMismatch)
        );
        // The oldest left out: numbered from one.
        assert_eq!(
            check_chain(&head, &KEY, &proof, &items[1..]),
            Err(Refusal::ChainIncomplete)
        );
        // The entry repeated.
        let doubled = vec![items[0].clone(), items[0].clone()];
        assert_eq!(
            check_chain(&head, &KEY, &proof, &doubled),
            Err(Refusal::ChainIncomplete)
        );
        // Garbage bytes, bytes of another version, and bytes that are not canonical.
        let mut garbage = items.clone();
        garbage[0].entry = vec![9; 20];
        assert_eq!(
            check_chain(&head, &KEY, &proof, &garbage),
            Err(Refusal::EntryEncoding)
        );
        // An entry not in the log of this head: a changed proof, a wrong index, a smaller size.
        let mut bad_proof = items.clone();
        bad_proof[1].inclusion_proof[0][0] ^= 1;
        assert_eq!(
            check_chain(&head, &KEY, &proof, &bad_proof),
            Err(Refusal::NotInLog)
        );
        let mut bad_index = items.clone();
        bad_index[1].index += 1;
        assert_eq!(
            check_chain(&head, &KEY, &proof, &bad_index),
            Err(Refusal::NotInLog)
        );
        let mut short = items.clone();
        short[1].inclusion_proof.pop();
        assert_eq!(
            check_chain(&head, &KEY, &proof, &short),
            Err(Refusal::NotInLog)
        );
        // An entry of another account served as this one's (it is in the log, but not filed here).
        let mut foreign = items.clone();
        let other = log.items(&[1; 32]);
        foreign[0] = ChainItem {
            chain_index: 0,
            ..other[0].clone()
        };
        assert_eq!(
            check_chain(&head, &KEY, &proof, &foreign),
            Err(Refusal::WrongChain)
        );
    }

    #[test]
    fn entries_must_link_and_follow_in_log_order() {
        // A chain whose second entry does not name the first.
        let mut log = Log::new(3);
        log.append(KEY, KIND_SERVICE_KEY, fields(), T0);
        log.append_entry(&Entry {
            kind: KIND_SERVICE_KEY,
            map: MapId::Service,
            map_key: KEY,
            prev: [5; 32],
            time_ms: T0,
            fields: fields(),
        });
        let head = checked(&mut log);
        assert_eq!(
            check_chain(&head, &KEY, &log.map_proof(&KEY), &log.items(&KEY)),
            Err(Refusal::ChainBroken)
        );
        // A first entry that claims a predecessor.
        let mut log = Log::new(3);
        log.append_entry(&Entry {
            kind: KIND_SERVICE_KEY,
            map: MapId::Service,
            map_key: KEY,
            prev: [5; 32],
            time_ms: T0,
            fields: fields(),
        });
        let head = checked(&mut log);
        assert_eq!(
            check_chain(&head, &KEY, &log.map_proof(&KEY), &log.items(&KEY)),
            Err(Refusal::ChainBroken)
        );
        // Linked, but served with the wrong log position: the proof does not hold at that index.
        // (The position order check in `check_chain` backs this up and is not reachable alone,
        // since a leaf is in the log once.)
        let mut log = log_two();
        let head = checked(&mut log);
        let mut items = log.items(&KEY);
        items.swap(0, 1);
        items[0].chain_index = 0;
        items[1].chain_index = 1;
        assert_eq!(
            check_chain(&head, &KEY, &log.map_proof(&KEY), &items),
            Err(Refusal::ChainBroken)
        );
    }

    fn log_two() -> Log {
        let mut log = Log::new(3);
        log.append(KEY, KIND_SERVICE_KEY, fields(), T0);
        log.append(KEY, KIND_SERVICE_KEY, fields(), T0);
        log
    }

    #[test]
    fn an_entry_of_the_identity_map_is_not_a_service_chain_entry() {
        let mut log = Log::new(3);
        log.append(KEY, KIND_SERVICE_KEY, fields(), T0);
        // Same account key, filed in the identity map: it must not count in the service chain.
        log.append_entry(&Entry {
            kind: KIND_SERVICE_KEY,
            map: MapId::Identity,
            map_key: KEY,
            prev: [0; 32],
            time_ms: T0,
            fields: fields(),
        });
        let head = checked(&mut log);
        let mut items = log.items(&KEY);
        assert_eq!(items.len(), 1, "the fixture only serves service entries");
        let identity_bytes = log.leaves[1].clone();
        let hashes: Vec<Hash> = log.leaves.iter().map(|b| leaf_hash(b)).collect();
        items.push(ChainItem {
            index: 1,
            chain_index: 1,
            entry: identity_bytes,
            inclusion_proof: crate::merkle::inclusion_proof(hashes.as_slice(), 1, log.size())
                .expect("ok"),
        });
        assert_eq!(
            check_chain(&head, &KEY, &log.map_proof(&KEY), &items),
            Err(Refusal::WrongChain)
        );
    }
}
