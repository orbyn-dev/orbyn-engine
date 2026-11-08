//! A small hashcash proof of work, for the sign-up start: the server hands out a challenge (random
//! bytes it can recognise again) and a number of bits; the client finds a `nonce` so that
//! `SHA-256("orbyn/signup-pow/v1" || challenge || nonce)` begins with that many zero bits. Checking
//! costs one hash; finding costs about `2^bits`. It runs on every device, in the browser too.

use sha2::{Digest, Sha256};

const LABEL: &[u8] = b"orbyn/signup-pow/v1";

/// The most bits the server asks for. A nonce is 32 bits, so more could not be solved.
pub const MAX_BITS: u32 = 28;

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

fn hash(challenge: &[u8], nonce: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update(challenge);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// Whether `nonce` solves `challenge` at `bits` bits.
pub fn verify(challenge: &[u8], nonce: u32, bits: u32) -> bool {
    bits <= MAX_BITS && leading_zero_bits(&hash(challenge, nonce)) >= bits
}

/// The first nonce that solves `challenge` at `bits` bits, counting up from 0, or `None` when none
/// of the 2^32 does (only possible for `bits` above [`MAX_BITS`], which is refused).
pub fn solve(challenge: &[u8], bits: u32) -> Option<u32> {
    solve_from(challenge, bits, 0)
}

/// The same, counting up from `start` and wrapping round. **A client starts from a random value**:
/// the server takes a solution once, and the challenge is the same for a prefix for ten minutes,
/// so two starts that both began at 0 would find the same nonce and the second would be refused.
pub fn solve_from(challenge: &[u8], bits: u32, start: u32) -> Option<u32> {
    if bits > MAX_BITS {
        return None;
    }
    (start..=u32::MAX)
        .chain(0..start)
        .find(|nonce| leading_zero_bits(&hash(challenge, *nonce)) >= bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_solution_verifies_at_its_bits_and_not_a_wrong_challenge_or_nonce() {
        let challenge = b"a challenge";
        let nonce = solve(challenge, 12).expect("a solution");
        assert!(verify(challenge, nonce, 12));
        assert!(
            verify(challenge, nonce, 8),
            "a stronger proof also meets a weaker ask"
        );
        // Another challenge has a different set of solutions (12 bits: about 1 in 4096 by chance).
        assert!((0..8).any(|i| !verify(format!("other {i}").as_bytes(), nonce, 12)));
        // A nonce that is not the first solution fails at a bit count only the first reaches.
        let hard = (0u32..)
            .find(|n| !verify(challenge, *n, 12))
            .expect("a failing nonce");
        assert!(!verify(challenge, hard, 12));
        assert!(
            !verify(challenge, nonce, MAX_BITS + 1),
            "more than the most is refused"
        );
        assert_eq!(solve(challenge, MAX_BITS + 1), None);
    }

    #[test]
    fn solving_from_another_start_finds_another_solution_and_wraps_round() {
        let challenge = b"a challenge";
        let first = solve(challenge, 10).expect("a solution");
        let other = solve_from(challenge, 10, first + 1).expect("another");
        assert_ne!(first, other);
        assert!(verify(challenge, other, 10));
        // Starting at the top of the range wraps to the bottom.
        let wrapped = solve_from(challenge, 10, u32::MAX).expect("wrapped");
        assert!(verify(challenge, wrapped, 10));
        assert_eq!(solve_from(challenge, 10, 0), Some(first));
    }

    #[test]
    fn zero_bits_always_verify_and_the_bit_count_is_exact() {
        assert!(verify(b"x", 0, 0));
        assert_eq!(leading_zero_bits(&[0, 0b0001_0000]), 11);
        assert_eq!(leading_zero_bits(&[0b1000_0000]), 0);
        assert_eq!(leading_zero_bits(&[0, 0, 0]), 24);
    }
}
