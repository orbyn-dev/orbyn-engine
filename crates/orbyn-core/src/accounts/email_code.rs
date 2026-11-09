//! The code mailed to prove an address: 8 characters from a 30-symbol alphabet (about 39 bits),
//! shown in two groups, `K7QM-R4TW`.
//!
//! The alphabet is the digits 2 to 9 and the letters A to Z without I, L, O and U: Crockford's
//! base32 without the symbols people confuse (0 and O, 1 and I and L) and without the 0 and 1 that
//! would be left to confuse. 30 symbols, so a character holds a little under 5 bits.
//!
//! Input is read as people type it: case does not matter and hyphens and spaces are ignored. No
//! other character is changed into a symbol (an `O` is not read as a `0`): there is no `0`.

/// The symbols, in order.
pub const ALPHABET: &[u8; 30] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters in a code.
pub const LEN: usize = 8;

/// The code that `bytes` stand for, drawn uniformly: a byte is used only below the largest
/// multiple of 30 that fits (240), so no symbol is likelier than another. `None` if the bytes run
/// out before 8 symbols were drawn (the caller asks for more).
pub fn from_bytes(bytes: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(LEN);
    for &b in bytes {
        if b < 240 {
            out.push(char::from(ALPHABET[usize::from(b) % ALPHABET.len()]));
            if out.len() == LEN {
                return Some(out);
            }
        }
    }
    None
}

/// What a person typed, as the code it stands for: letters upper-cased, and spaces, hyphens and the
/// dashes a word processor makes of them removed.
pub fn normalise(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '\u{2010}'..='\u{2015}' | '\u{2212}'))
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Whether `text` is exactly a code (8 symbols, no grouping).
pub fn is_code(text: &str) -> bool {
    text.len() == LEN && text.bytes().all(|b| ALPHABET.contains(&b))
}

/// `K7QM-R4TW` for a code; any other text as it is.
pub fn grouped(code: &str) -> String {
    if is_code(code) {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_alphabet_has_thirty_symbols_and_none_that_look_alike() {
        assert_eq!(ALPHABET.len(), 30);
        for confusable in b"01OIL" {
            assert!(
                !ALPHABET.contains(confusable),
                "{}",
                char::from(*confusable)
            );
        }
        assert!(!ALPHABET.contains(&b'U'));
        let mut sorted = ALPHABET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 30, "no symbol twice");
        assert!(
            ALPHABET
                .iter()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        );
    }

    #[test]
    fn bytes_make_a_uniform_code_skipping_the_bytes_that_would_skew_it() {
        // Every symbol is drawn from exactly 8 of the 240 bytes below the cut.
        let mut counts = [0usize; 30];
        for b in 0..240u8 {
            counts[usize::from(b) % 30] += 1;
        }
        assert!(counts.iter().all(|c| *c == 8));
        let code = from_bytes(&[0, 1, 2, 3, 4, 5, 6, 7]).expect("a code");
        assert_eq!(code, "23456789");
        // Bytes at or above 240 are skipped, and too few bytes make no code.
        assert_eq!(
            from_bytes(&[255, 240, 0, 1, 2, 3, 4, 5, 6, 7]).as_deref(),
            Some("23456789")
        );
        assert_eq!(from_bytes(&[0, 1, 2]), None);
        assert!(is_code(&code));
    }

    #[test]
    fn what_people_type_is_read_as_the_code_and_nothing_else_is_changed_into_one() {
        for typed in [
            "k7qm-r4tw",
            "K7QM R4TW",
            " k7qm\tr4tw ",
            "K7QMR4TW",
            "K7QM\u{2013}R4TW",
            "k7-qm-r4-tw",
        ] {
            assert_eq!(normalise(typed), "K7QMR4TW", "{typed:?}");
        }
        // An O is not a 0 and an I is not a 1: there is neither in a code, so those never match.
        assert_eq!(normalise("K7QM-R4T0"), "K7QMR4T0");
        assert!(!is_code(&normalise("K7QM-R4T0")));
        assert!(is_code("K7QMR4TW"));
        assert!(!is_code("K7QMR4T") && !is_code("K7QMR4TWW") && !is_code("k7qmr4tw"));
    }

    #[test]
    fn a_code_is_shown_in_two_groups_of_four() {
        assert_eq!(grouped("K7QMR4TW"), "K7QM-R4TW");
        assert_eq!(grouped("1234"), "1234");
        assert_eq!(grouped("k7qmr4tw"), "k7qmr4tw", "only a code is grouped");
    }
}
