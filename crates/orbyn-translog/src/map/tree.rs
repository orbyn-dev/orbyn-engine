//! The in-memory reference map and its node construction.

use super::*;

/// An in-memory map, the reference the proofs and updates are checked against.
#[derive(Debug, Clone, Default)]
pub struct Map {
    entries: BTreeMap<Key, Hash>,
}

impl Map {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sets a key, returning its previous value.
    pub fn insert(&mut self, key: Key, value: Hash) -> Option<Hash> {
        self.entries.insert(key, value)
    }

    pub fn get(&self, key: &Key) -> Option<&Hash> {
        self.entries.get(key)
    }

    pub fn root(&self) -> Hash {
        let all: Vec<(Key, Hash)> = self.entries.iter().map(|(k, v)| (*k, *v)).collect();
        node(&all)
    }

    /// The proof for `key`: membership if it is in the map, otherwise non-membership.
    pub fn prove(&self, key: &Key) -> Proof {
        let mut range: Vec<(Key, Hash)> = self.entries.iter().map(|(k, v)| (*k, *v)).collect();
        let mut steps = Vec::new();
        while range.len() > 1 {
            let (index, split) = split_range(&range);
            let (left, right) = range.split_at(split);
            let (next, other) = if bit(key, index) {
                (right, left)
            } else {
                (left, right)
            };
            steps.push(Step {
                index: u16::try_from(index).expect("below 256"),
                sibling: node(other),
            });
            range = next.to_vec();
        }
        let end = match range.first() {
            Some((key, value)) => End::Leaf {
                key: *key,
                value: *value,
            },
            None => End::Empty,
        };
        Proof { steps, end }
    }
}

/// For a sorted range of at least two keys: the first bit where they differ (the first and last
/// key differ there first, and nowhere before) and the position where that bit turns to one.
fn split_range(range: &[(Key, Hash)]) -> (usize, usize) {
    let index = first_diff(&range[0].0, &range[range.len() - 1].0);
    let split = range.partition_point(|(k, _)| !bit(k, index));
    (index, split)
}

fn node(range: &[(Key, Hash)]) -> Hash {
    match range {
        [] => map_empty_root(),
        [(key, value)] => map_leaf_hash(key, value),
        _ => {
            let (index, split) = split_range(range);
            let (left, right) = range.split_at(split);
            map_branch_hash(
                u16::try_from(index).expect("below 256"),
                &node(left),
                &node(right),
            )
        }
    }
}
