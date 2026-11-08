//! A small in-memory log for tests of the verifier, here and in the client: it builds entries,
//! the service map, signed and cosigned heads, and the proofs a key service would serve. Not for
//! production; behind the `test-support` feature.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};

use crate::cosign::{Cosignature, cosign_message};
use crate::entry::{Entry, MapId, map_value};
use crate::head::UnsignedHead;
use crate::map::Map;
use crate::merkle::{Hash, consistency_proof, inclusion_proof, leaf_hash, tree_root};
use crate::verify::{ChainItem, Pins, SignedHead};

/// The time every entry and head in the fixture starts from, in milliseconds.
pub const T0: u64 = 1_800_000_000_000;

#[derive(Clone)]
pub struct Log {
    pub log_key: SigningKey,
    pub witnesses: Vec<SigningKey>,
    /// Canonical bytes of every entry, in log order.
    pub leaves: Vec<Vec<u8>>,
    map: Map,
    chains: BTreeMap<[u8; 32], Vec<Hash>>,
    previous_head: Hash,
}

impl Log {
    pub fn new(witnesses: u8) -> Self {
        Self {
            log_key: SigningKey::from_bytes(&[41; 32]),
            witnesses: (0..witnesses)
                .map(|i| SigningKey::from_bytes(&[100 + i; 32]))
                .collect(),
            leaves: Vec::new(),
            map: Map::new(),
            chains: BTreeMap::new(),
            previous_head: [0; 32],
        }
    }

    pub fn pins(&self, threshold: usize) -> Pins {
        Pins {
            log_keys: vec![(1, self.log_key.verifying_key().to_bytes())],
            witnesses: self
                .witnesses
                .iter()
                .map(|w| w.verifying_key().to_bytes())
                .collect(),
            threshold,
        }
    }

    /// Appends an entry exactly as given (its `prev` is not touched) and updates the account's
    /// map value. Returns its log index.
    pub fn append_entry(&mut self, entry: &Entry) -> u64 {
        let bytes = entry.encode().unwrap();
        let hash = leaf_hash(&bytes);
        self.leaves.push(bytes);
        let chain = self.chains.entry(entry.map_key).or_default();
        chain.push(hash);
        if entry.map == MapId::Service {
            self.map
                .insert(entry.map_key, map_value(&hash, chain.len() as u64));
        }
        self.leaves.len() as u64 - 1
    }

    /// Appends an entry of `kind` to the service-map chain of `map_key`, linked to the chain's
    /// last entry.
    pub fn append(&mut self, map_key: [u8; 32], kind: u8, fields: Vec<u8>, time_ms: u64) -> u64 {
        let prev = self
            .chains
            .get(&map_key)
            .and_then(|c| c.last().copied())
            .unwrap_or([0; 32]);
        self.append_entry(&Entry {
            kind,
            map: MapId::Service,
            map_key,
            prev,
            time_ms,
            fields,
        })
    }

    fn hashes(&self) -> Vec<Hash> {
        self.leaves.iter().map(|b| leaf_hash(b)).collect()
    }

    /// The root of the log as it stands.
    pub fn log_root(&self) -> Hash {
        tree_root(self.hashes().as_slice())
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// A head of the log as it stands, signed by the log key and cosigned at `witness_ms` by the
    /// witnesses at `signing` (indices into `witnesses`).
    pub fn head_at(&mut self, witness_ms: u64, signing: &[usize]) -> SignedHead {
        let head = UnsignedHead {
            size: self.size(),
            log_root: self.log_root(),
            service_map_root: self.map.root(),
            identity_map_root: [0; 32],
            time_ms: witness_ms,
            prev_head_hash: self.previous_head,
            log_key_version: 1,
        };
        self.previous_head = head.hash();
        self.sign(head, witness_ms, signing)
    }

    /// Signs and cosigns `head` as given.
    pub fn sign(&self, head: UnsignedHead, witness_ms: u64, signing: &[usize]) -> SignedHead {
        let log_signature = self.log_key.sign(&head.encode()).to_bytes();
        let hash = head.hash();
        let cosignatures = signing
            .iter()
            .map(|&i| {
                let key = &self.witnesses[i];
                let signature = key.sign(&cosign_message(&hash, witness_ms)).to_bytes();
                (
                    key.verifying_key().to_bytes(),
                    Cosignature {
                        head_hash: hash,
                        time_ms: witness_ms,
                        signature,
                    },
                )
            })
            .collect();
        SignedHead {
            head,
            log_signature,
            cosignatures,
        }
    }

    /// A head cosigned by every witness at `T0`.
    pub fn head(&mut self) -> SignedHead {
        let all: Vec<usize> = (0..self.witnesses.len()).collect();
        self.head_at(T0, &all)
    }

    /// The encoded map proof for `key`, against the map as it stands.
    pub fn map_proof(&self, key: &[u8; 32]) -> Vec<u8> {
        self.map.prove(key).encode().unwrap()
    }

    /// The whole chain of `key`, each entry with its inclusion proof against the log as it stands.
    pub fn items(&self, key: &[u8; 32]) -> Vec<ChainItem> {
        let hashes = self.hashes();
        let size = self.size();
        let mut items = Vec::new();
        for (index, bytes) in self.leaves.iter().enumerate() {
            let entry = Entry::decode(bytes).unwrap();
            if &entry.map_key == key && entry.map == MapId::Service {
                items.push(ChainItem {
                    index: index as u64,
                    chain_index: items.len() as u64,
                    entry: bytes.clone(),
                    inclusion_proof: inclusion_proof(hashes.as_slice(), index as u64, size)
                        .unwrap(),
                });
            }
        }
        items
    }

    /// The consistency proof from the first `from` entries to the log as it stands.
    pub fn consistency(&self, from: u64) -> Vec<Hash> {
        consistency_proof(self.hashes().as_slice(), from, self.size()).unwrap()
    }
}
