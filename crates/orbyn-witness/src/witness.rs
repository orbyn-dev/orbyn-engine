//! The witness core: it checks and accepts heads, and turns each one into a cosignature.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey};
use orbyn_translog::map::{Lookup, Map, update, verify};
use orbyn_translog::merkle::{Accumulator, verify_consistency};
use orbyn_translog::{Cosignature, Entry, Hash, MapId, cosign_message, map_value};

use crate::clock::Clock;
use crate::reason::{CosignError, Held, Reason, Refusal, ReplayCause, StartError, refuse};
use crate::state::{SignedHead, State, StateStore, StoreError};
use crate::types::{Config, CosignEntry, CosignRequest, PinnedHead};

/// A witness over a state store and a clock.
pub struct Witness<S: StateStore, C: Clock> {
    key: SigningKey,
    config: Config,
    store: S,
    clock: C,
    state: Mutex<State>,
    /// This witness's own newest cosignature, set under the state's lock.
    cosigned: Mutex<Option<Cosignature>>,
}

fn slot(map: MapId) -> usize {
    match map {
        MapId::Service => 0,
        MapId::Identity => 1,
    }
}

impl<S: StateStore, C: Clock> Witness<S, C> {
    /// Starts from saved state. With none, it refuses: an emptied directory must not pass for a
    /// new witness. Use a bootstrap for a first start.
    pub fn open(key: SigningKey, config: Config, store: S, clock: C) -> Result<Self, StartError> {
        let state = store.load()?.ok_or(StartError::NeedsBootstrap)?;
        Ok(Self {
            key,
            config,
            store,
            clock,
            state: Mutex::new(state),
            cosigned: Mutex::new(None),
        })
    }

    /// A first start from the empty log: size 0, both maps empty. Refuses if state exists.
    pub fn bootstrap_empty(
        key: SigningKey,
        config: Config,
        store: S,
        clock: C,
    ) -> Result<Self, StartError> {
        if store.load()?.is_some() {
            return Err(StartError::AlreadyStarted);
        }
        let state = State::genesis();
        store.save(&state)?;
        Ok(Self {
            key,
            config,
            store,
            clock,
            state: Mutex::new(state),
            cosigned: Mutex::new(None),
        })
    }

    /// A first start at a later head, by **replaying the whole log**: every entry, in order, onto
    /// empty maps. The witness computes both map roots itself and checks the log root and size it
    /// gets are the pinned ones; the pin carries no map root to trust. Refuses if state exists.
    pub fn bootstrap_replay(
        key: SigningKey,
        config: Config,
        store: S,
        clock: C,
        entries: &[Entry],
        pinned: &PinnedHead,
    ) -> Result<Self, StartError> {
        if store.load()?.is_some() {
            return Err(StartError::AlreadyStarted);
        }
        let mut state = replay(entries, pinned, &config)?;
        // A pinned head counts as final only if it is within the skew of this clock now.
        if pinned.head.time_ms.abs_diff(clock.now_ms()) > config.max_skew_ms {
            state.final_head = None;
        }
        store.save(&state)?;
        Ok(Self {
            key,
            config,
            store,
            clock,
            state: Mutex::new(state),
            cosigned: Mutex::new(None),
        })
    }

    /// The witness's public key.
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The state right now.
    pub fn state(&self) -> State {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sign(&self, head_hash: Hash, now: u64) -> Cosignature {
        let signature = self.key.sign(&cosign_message(&head_hash, now)).to_bytes();
        Cosignature {
            head_hash,
            time_ms: now,
            signature,
        }
    }

    /// Signs the last head accepted **as final** again, with this witness's time now: **the
    /// witness's own schedule**. A log that is idle, or whose key service has gone quiet, still
    /// shows a fresh cosignature of the newest head the witness knows, so a device can tell a key
    /// service that is withholding from one that is simply between heads. It changes no state.
    /// A head accepted only as intermediate (an old stop on a catch-up) is never re-cosigned: with
    /// none final yet, this is `None`.
    pub fn recosign_latest(&self) -> Option<Cosignature> {
        let state = self.lock();
        let hash = state.final_head.as_ref()?.head.hash();
        let cosignature = self.sign(hash, self.clock.now_ms());
        *self.last_cosignature() = Some(cosignature.clone());
        Some(cosignature)
    }

    /// The newest head this witness accepted **as final**, as it is saved: the head, the log key's
    /// signature, and **this witness's own newest cosignature** of it. Read from the state itself
    /// under its lock. A head accepted only as intermediate is kept for the chain's linkage and is
    /// never served here. `None` before the first final head.
    pub fn newest(&self) -> Option<(SignedHead, Cosignature)> {
        let state = self.lock();
        let signed = state.final_head.clone()?;
        let hash = signed.head.hash();
        let mut last = self.last_cosignature();
        // After a restart there is none yet: sign the saved head with the time now.
        let cosignature = match last.as_ref() {
            Some(c) if c.head_hash == hash => c.clone(),
            _ => {
                let fresh = self.sign(hash, self.clock.now_ms());
                *last = Some(fresh.clone());
                fresh
            }
        };
        Some((signed, cosignature))
    }

    fn last_cosignature(&self) -> std::sync::MutexGuard<'_, Option<Cosignature>> {
        self.cosigned.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Checks a request and, if every check passes, saves the new state **and then** answers with
    /// a cosignature. A refusal, or a state that could not be saved, changes nothing and signs
    /// nothing.
    ///
    /// **A head on the way to the final one is never signed.** A request marked `intermediate` is
    /// checked in full and moves the witness's state forward (that is how a witness that was away
    /// catches up through the chain), and is answered with no cosignature at all: a witness signs
    /// only the head that ends a request, and only within its clock window. So `None` is the
    /// whole answer to an intermediate head, and a `Some` is always of a final one.
    pub fn accept(&self, request: &CosignRequest) -> Result<Option<Cosignature>, CosignError> {
        let mut state = self.lock();
        let head = &request.head;

        // 1. The log signature, from a pinned log key.
        let public = self
            .config
            .log_keys
            .iter()
            .find(|(version, _)| *version == head.log_key_version)
            .map(|(_, key)| key)
            .ok_or_else(|| refuse(Reason::BadSignature, "no pinned log key has this version"))?;
        if !head.verify(public, &request.log_signature) {
            return Err(refuse(Reason::BadSignature, "the log signature does not verify").into());
        }

        let held = || Held {
            size: state.size,
            log_root: state.log_root,
            service_map_root: state.service_map_root,
            identity_map_root: state.identity_map_root,
            head_hash: state.head_hash,
            head: state.head.clone(),
        };
        let rollback = |detail: &'static str| Refusal {
            reason: Reason::Rollback,
            detail,
            held: Some(Box::new(held())),
        };
        let fork = |detail: &'static str| Refusal {
            reason: Reason::Fork,
            detail,
            held: Some(Box::new(held())),
        };

        // 2. Time: not before the last head's, and near this witness's clock.
        let now = self.clock.now_ms();
        if head.time_ms < state.head_time_ms {
            return Err(rollback("the head's time is before the last head's").into());
        }
        // The head that ends the request is within the skew of this clock. One on the way to a
        // later head (a witness catching up) may be older, as it was away, but never ahead of
        // the clock by more than the skew: a head dated far ahead would leave no later head able
        // to follow it.
        let ahead = head.time_ms.saturating_sub(now) > self.config.max_skew_ms;
        if ahead || (!request.intermediate && head.time_ms.abs_diff(now) > self.config.max_skew_ms)
        {
            return Err(refuse(
                Reason::ClockSkew,
                "the head's time is too far from this witness's clock",
            )
            .into());
        }

        // The very head already cosigned, asked again (a retry, or a fresh time for freshness):
        // the same size and the same roots as the state, as well as the same hash.
        if head.hash() == state.head_hash
            && head.size == state.size
            && head.log_root == state.log_root
            && head.service_map_root == state.service_map_root
            && head.identity_map_root == state.identity_map_root
        {
            // Asked again as a final head, and within the skew (checked above): it is final now.
            // That is a change of the saved state, so it is saved before it is answered.
            let promoted = !request.intermediate
                && state.final_head.as_ref().map(|f| f.head.hash()) != Some(state.head_hash);
            if promoted {
                let mut next = state.clone();
                next.final_head = next.head.clone();
                self.store.save(&next)?;
                *state = next;
            }
            if request.intermediate {
                return Ok(None);
            }
            let cosignature = self.sign(state.head_hash, now);
            *self.last_cosignature() = Some(cosignature.clone());
            return Ok(Some(cosignature));
        }
        if head.size < state.size {
            return Err(rollback("the head is smaller than the last one").into());
        }

        let mut next = state.clone();
        if head.size == state.size {
            // Same size: either an idle head (same roots, a new time) or a fork.
            if head.log_root != state.log_root
                || head.service_map_root != state.service_map_root
                || head.identity_map_root != state.identity_map_root
            {
                return Err(fork("a different head at a size already signed").into());
            }
            if !request.entries.is_empty() || !request.consistency_proof.is_empty() {
                return Err(refuse(Reason::BadRequest, "an idle head carries no entries").into());
            }
            if head.prev_head_hash != state.head_hash {
                return Err(fork("the head does not extend the last one").into());
            }
        } else {
            let wanted = head.size - state.size;
            if wanted > self.config.max_entries as u64 || request.entries.len() as u64 != wanted {
                return Err(refuse(
                    Reason::BadRequest,
                    "the number of entries is not the growth of the log",
                )
                .into());
            }
            if head.prev_head_hash != state.head_hash {
                return Err(fork("the head does not extend the last one").into());
            }
            // 3. The log extends: the proof, and the entries' leaves on our own frontier.
            verify_consistency(
                state.size,
                head.size,
                &state.log_root,
                &head.log_root,
                &request.consistency_proof,
            )
            .map_err(|_| refuse(Reason::BadProof, "the consistency proof does not verify"))?;
            let mut accumulator = Accumulator::from_frontier(state.size, state.frontier.clone())
                .map_err(|_| StoreError::Corrupt)?;
            for item in &request.entries {
                let leaf = item
                    .entry
                    .hash()
                    .map_err(|_| refuse(Reason::BadRequest, "an entry cannot be encoded"))?;
                accumulator.append(leaf);
            }
            if accumulator.root() != head.log_root {
                return Err(refuse(
                    Reason::BadProof,
                    "the entries do not give the head's log root",
                )
                .into());
            }
            // 4. The maps: each entry applied to our own roots, and only those.
            let mut roots = [state.service_map_root, state.identity_map_root];
            for item in &request.entries {
                let i = slot(item.entry.map);
                roots[i] = apply(&roots[i], item)?;
            }
            if roots != [head.service_map_root, head.identity_map_root] {
                return Err(refuse(
                    Reason::MapMismatch,
                    "the map roots are not what the entries give",
                )
                .into());
            }
            next.size = head.size;
            next.log_root = head.log_root;
            next.service_map_root = roots[0];
            next.identity_map_root = roots[1];
            next.frontier = accumulator.frontier().to_vec();
        }
        next.head_hash = head.hash();
        next.head_time_ms = head.time_ms;
        next.head = Some(SignedHead {
            head: head.clone(),
            log_signature: request.log_signature,
        });
        // Only a head accepted as final becomes what the witness serves and cosigns again.
        if !request.intermediate {
            next.final_head = next.head.clone();
        }

        // Durable before it is answered.
        self.store.save(&next)?;
        *state = next;
        if request.intermediate {
            return Ok(None);
        }
        let cosignature = self.sign(head.hash(), now);
        *self.last_cosignature() = Some(cosignature.clone());
        Ok(Some(cosignature))
    }

    /// [`Witness::accept`] for a request that ends a catch-up: the cosignature of its head. An
    /// `intermediate` request is refused here as a bad request, since it has no cosignature to
    /// give (use [`Witness::accept`]).
    pub fn cosign(&self, request: &CosignRequest) -> Result<Cosignature, CosignError> {
        // Refused before anything is checked or saved: nothing changes.
        if request.intermediate {
            return Err(refuse(
                Reason::BadRequest,
                "a head on the way to another is not signed",
            )
            .into());
        }
        self.accept(request)?.ok_or_else(|| {
            refuse(
                Reason::BadRequest,
                "a head on the way to another is not signed",
            )
            .into()
        })
    }
}

/// Applies one entry to a map root and returns the new root, or says why it does not apply.
fn apply(root: &Hash, item: &CosignEntry) -> Result<Hash, Refusal> {
    let entry = &item.entry;
    let hash = entry
        .hash()
        .map_err(|_| refuse(Reason::BadRequest, "an entry cannot be encoded"))?;
    let lookup = verify(root, &entry.map_key, &item.path).map_err(|_| {
        refuse(
            Reason::BadProof,
            "a map path does not prove the key under the root",
        )
    })?;
    // The old value must be the account's chain as the entry says it continues it.
    match lookup {
        Lookup::Absent => {
            if entry.prev != [0; 32] || item.chain_len != 0 {
                return Err(refuse(
                    Reason::MapMismatch,
                    "the entry continues a chain the map does not have",
                ));
            }
        }
        Lookup::Present(old) => {
            if entry.prev == [0; 32]
                || item.chain_len == 0
                || old != map_value(&entry.prev, item.chain_len)
            {
                return Err(refuse(
                    Reason::MapMismatch,
                    "the entry does not continue its account's chain",
                ));
            }
        }
    }
    let value = map_value(&hash, item.chain_len + 1);
    update(root, &entry.map_key, &value, &item.path).map_err(|_| {
        refuse(
            Reason::BadProof,
            "a map path does not update under the root",
        )
    })
}

/// Replays a whole log onto empty maps.
fn replay(entries: &[Entry], pinned: &PinnedHead, config: &Config) -> Result<State, StartError> {
    let head = &pinned.head;
    // The pinned head is signed by a pinned log key: nothing in it is taken on trust.
    config
        .log_keys
        .iter()
        .find(|(version, _)| *version == head.log_key_version)
        .map(|(_, key)| key)
        .filter(|key| head.verify(key, &pinned.log_signature))
        .ok_or(StartError::Replay(ReplayCause::Signature))?;
    if entries.len() as u64 != head.size {
        return Err(StartError::Replay(ReplayCause::Size));
    }
    let mut maps = [Map::new(), Map::new()];
    let mut chains: HashMap<(usize, [u8; 32]), (Hash, u64)> = HashMap::new();
    let mut accumulator = Accumulator::new();
    for entry in entries {
        let hash = entry
            .hash()
            .map_err(|_| StartError::Replay(ReplayCause::Entries))?;
        let key = (slot(entry.map), entry.map_key);
        let (last, len) = chains.get(&key).copied().unwrap_or(([0; 32], 0));
        if entry.prev != last {
            return Err(StartError::Replay(ReplayCause::Chain));
        }
        chains.insert(key, (hash, len + 1));
        maps[key.0].insert(entry.map_key, map_value(&hash, len + 1));
        accumulator.append(hash);
    }
    if accumulator.root() != head.log_root {
        return Err(StartError::Replay(ReplayCause::LogRoot));
    }
    // The maps the entries give are the maps the head says, both of them.
    if maps[0].root() != head.service_map_root || maps[1].root() != head.identity_map_root {
        return Err(StartError::Replay(ReplayCause::MapRoots));
    }
    Ok(State {
        size: head.size,
        log_root: head.log_root,
        service_map_root: head.service_map_root,
        identity_map_root: head.identity_map_root,
        head_hash: head.hash(),
        head_time_ms: head.time_ms,
        frontier: accumulator.frontier().to_vec(),
        head: Some(SignedHead {
            head: head.clone(),
            log_signature: pinned.log_signature,
        }),
        final_head: Some(SignedHead {
            head: head.clone(),
            log_signature: pinned.log_signature,
        }),
    })
}
