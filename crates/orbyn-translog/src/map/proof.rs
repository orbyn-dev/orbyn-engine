//! Path-compressed sparse Merkle map proofs and the update function.

use super::*;

/// One branch on the walk: its bit index and the hash of the child the walk did not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub index: u16,
    pub sibling: Hash,
}

/// Where the walk ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The map is empty.
    Empty,
    /// The one leaf the walk reaches.
    Leaf { key: Key, value: Hash },
}

/// What a proof shows for the key it was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Present(Hash),
    Absent,
}

/// The walk from the root to the leaf a key reaches. Steps are root first, with strictly
/// increasing indices below 256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub steps: Vec<Step>,
    pub end: End,
}

impl Proof {
    /// The canonical bytes: the step count (u16 big endian), each step as its index (u16 big
    /// endian) and sibling, then `0x00` for an empty map or `0x01 ‖ key ‖ value` for a leaf.
    ///
    /// A proof is at most 256 steps (indices strictly increase below 256), which is what
    /// [`Proof::decode`] accepts; one with more is [`MapError::BadProof`], not a panic.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.steps.len() > KEY_BITS {
            return Err(MapError::BadProof);
        }
        let count = u16::try_from(self.steps.len()).map_err(|_| MapError::BadProof)?;
        let mut out = Vec::with_capacity(2 + self.steps.len() * STEP_LEN + 65);
        out.extend_from_slice(&count.to_be_bytes());
        for s in &self.steps {
            out.extend_from_slice(&s.index.to_be_bytes());
            out.extend_from_slice(&s.sibling);
        }
        match &self.end {
            End::Empty => out.push(0x00),
            End::Leaf { key, value } => {
                out.push(0x01);
                out.extend_from_slice(key);
                out.extend_from_slice(value);
            }
        }
        Ok(out)
    }

    /// Reads canonical bytes. It rejects trailing bytes, an unknown end tag, more than 256 steps,
    /// and indices that are not strictly increasing and below 256.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (count, mut rest) = bytes.split_first_chunk::<2>().ok_or(MapError::Encoding)?;
        let count = usize::from(u16::from_be_bytes(*count));
        if count > KEY_BITS {
            return Err(MapError::Encoding);
        }
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            let (index, r) = rest.split_first_chunk::<2>().ok_or(MapError::Encoding)?;
            let (sibling, r) = r.split_first_chunk::<32>().ok_or(MapError::Encoding)?;
            steps.push(Step {
                index: u16::from_be_bytes(*index),
                sibling: *sibling,
            });
            rest = r;
        }
        let (tag, rest) = rest.split_first().ok_or(MapError::Encoding)?;
        let end = match tag {
            0x00 => {
                // An empty map has no branches to walk.
                if !rest.is_empty() || !steps.is_empty() {
                    return Err(MapError::Encoding);
                }
                End::Empty
            }
            0x01 => {
                let (key, r) = rest.split_first_chunk::<32>().ok_or(MapError::Encoding)?;
                let (value, r) = r.split_first_chunk::<32>().ok_or(MapError::Encoding)?;
                if !r.is_empty() {
                    return Err(MapError::Encoding);
                }
                End::Leaf {
                    key: *key,
                    value: *value,
                }
            }
            _ => return Err(MapError::Encoding),
        };
        let proof = Proof { steps, end };
        check_indices(&proof.steps).map_err(|_| MapError::Encoding)?;
        Ok(proof)
    }
}

fn check_indices(steps: &[Step]) -> Result<()> {
    let mut previous: Option<u16> = None;
    for s in steps {
        if usize::from(s.index) >= KEY_BITS || previous.is_some_and(|p| s.index <= p) {
            return Err(MapError::BadProof);
        }
        previous = Some(s.index);
    }
    Ok(())
}

/// Folds `node` up through `steps` (root first), taking the side of each branch from `key`.
fn fold(key: &Key, mut node: Hash, steps: &[Step]) -> Hash {
    for s in steps.iter().rev() {
        node = if bit(key, usize::from(s.index)) {
            map_branch_hash(s.index, &s.sibling, &node)
        } else {
            map_branch_hash(s.index, &node, &s.sibling)
        };
    }
    node
}

/// Checks the proof's shape and that it hashes up to `root` for `key`, and says what it shows.
///
/// The end leaf must agree with `key` on every branch bit of the walk; that is what ties it to
/// this key's path and makes a non-membership proof sound.
pub fn verify(root: &Hash, key: &Key, proof: &Proof) -> Result<Lookup> {
    check_indices(&proof.steps)?;
    let (start, lookup) = match &proof.end {
        End::Empty => {
            if !proof.steps.is_empty() {
                return Err(MapError::BadProof);
            }
            (map_empty_root(), Lookup::Absent)
        }
        End::Leaf { key: found, value } => {
            if proof
                .steps
                .iter()
                .any(|s| bit(found, usize::from(s.index)) != bit(key, usize::from(s.index)))
            {
                return Err(MapError::BadProof);
            }
            let lookup = if found == key {
                Lookup::Present(*value)
            } else {
                Lookup::Absent
            };
            (map_leaf_hash(found, value), lookup)
        }
    };
    if fold(key, start, &proof.steps) == *root {
        Ok(lookup)
    } else {
        Err(MapError::RootMismatch)
    }
}

/// The root after setting `key` to `value`, given the proof for `key` as the map stood under
/// `root`. The proof is verified first; a bad one is an error and no root comes out.
pub fn update(root: &Hash, key: &Key, value: &Hash, proof: &Proof) -> Result<Hash> {
    let lookup = verify(root, key, proof)?;
    let new_leaf = map_leaf_hash(key, value);
    match (&proof.end, lookup) {
        // The key is already there: only its leaf changes.
        (_, Lookup::Present(_)) => Ok(fold(key, new_leaf, &proof.steps)),
        // An empty map: the new leaf is the whole tree.
        (End::Empty, _) => Ok(new_leaf),
        // Another leaf sits where the key belongs: a branch at the first bit where they differ
        // goes in below every step with a smaller index and above the rest. The verifier has
        // checked the keys agree on every step's bit, so no step has index `j`.
        (
            End::Leaf {
                key: found,
                value: found_value,
            },
            Lookup::Absent,
        ) => {
            let j = first_diff(key, found);
            let above = proof
                .steps
                .iter()
                .take_while(|s| usize::from(s.index) < j)
                .count();
            let below = fold(
                found,
                map_leaf_hash(found, found_value),
                &proof.steps[above..],
            );
            let index = u16::try_from(j).expect("below 256");
            let joined = if bit(key, j) {
                map_branch_hash(index, &below, &new_leaf)
            } else {
                map_branch_hash(index, &new_leaf, &below)
            };
            Ok(fold(key, joined, &proof.steps[..above]))
        }
    }
}
