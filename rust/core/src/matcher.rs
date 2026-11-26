//! Case-insensitive hexadecimal prefix/postfix matching over the 32-character
//! address, and validation of the patterns.
//!
//! Port of matcher.go (`newAddressMatcher`, `hexNibble`, `matches`) and
//! config.go (`validatePatterns`, `isHex`). The matcher uses one `u128` mask
//! and value over the big-endian address instead of Go's nibble layout; the
//! meaning is the same, including odd nibble boundaries.
//!
//! Adapted from the Rust rewrite by sozidatel (https://github.com/sozidatel),
//! basis snapshot 2026-11-25.

use core::fmt;

/// Length of the address in hexadecimal characters (Go `addressHexLength`).
const ADDRESS_HEX_LENGTH: usize = 32;

/// A rejected pattern. `Display` is Go's message, verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternError {
    /// Both patterns are empty.
    Empty,
    /// The prefix is longer than 32 bytes.
    PrefixTooLong,
    /// The postfix is longer than 32 bytes.
    PostfixTooLong,
    /// The prefix holds a byte outside `[0-9a-fA-F]`.
    PrefixNotHex,
    /// The postfix holds a byte outside `[0-9a-fA-F]`.
    PostfixNotHex,
    /// The two patterns together are longer than 32 bytes.
    CombinedTooLong,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "at least one of --prefix or --postfix must be specified",
            Self::PrefixTooLong => "prefix must be 1-32 hex characters",
            Self::PostfixTooLong => "postfix must be 1-32 hex characters",
            Self::PrefixNotHex => "prefix must contain only hex characters [0-9a-fA-F]",
            Self::PostfixNotHex => "postfix must contain only hex characters [0-9a-fA-F]",
            Self::CombinedTooLong => {
                "combined prefix and postfix length must not exceed 32 hex characters"
            }
        })
    }
}

impl std::error::Error for PatternError {}

/// Port of config.go `validatePatterns`: the same checks in the same order.
/// The arguments are the raw bytes of the already-lowercased flag values.
pub fn validate_patterns(prefix: &[u8], postfix: &[u8]) -> Result<(), PatternError> {
    if prefix.is_empty() && postfix.is_empty() {
        return Err(PatternError::Empty);
    }
    if prefix.len() > ADDRESS_HEX_LENGTH {
        return Err(PatternError::PrefixTooLong);
    }
    if postfix.len() > ADDRESS_HEX_LENGTH {
        return Err(PatternError::PostfixTooLong);
    }
    if !prefix.iter().all(u8::is_ascii_hexdigit) {
        return Err(PatternError::PrefixNotHex);
    }
    if !postfix.iter().all(u8::is_ascii_hexdigit) {
        return Err(PatternError::PostfixNotHex);
    }
    // Both lengths are at most 32 here, so the sum cannot overflow.
    if prefix.len().saturating_add(postfix.len()) > ADDRESS_HEX_LENGTH {
        return Err(PatternError::CombinedTooLong);
    }
    Ok(())
}

/// Port of matcher.go `hexNibble`.
const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Folds a pattern into a (mask, value) pair aligned to the low end.
/// `None` if a byte is not hexadecimal. At most 32 nibbles fit, so the
/// shifts only drop bits that are already zero.
fn fold(pattern: &[u8]) -> Option<(u128, u128)> {
    let mut mask = 0u128;
    let mut value = 0u128;
    for &c in pattern {
        mask = (mask << 4) | 0xf;
        value = (value << 4) | u128::from(hex_nibble(c)?);
    }
    Some((mask, value))
}

/// Matches the address against a hexadecimal prefix and postfix.
#[derive(Clone, Debug)]
pub struct Matcher {
    mask: u128,
    value: u128,
}

impl Matcher {
    /// Port of matcher.go `newAddressMatcher`. Nibble `i` of the 32-character
    /// address sits at bit shift `(31 - i) * 4`; the prefix covers the high
    /// nibbles and the postfix the low ones.
    pub fn new(prefix: &[u8], postfix: &[u8]) -> Result<Self, PatternError> {
        validate_patterns(prefix, postfix)?;
        // `validate_patterns` already ruled out non-hex bytes; these errors
        // mirror Go's second check and cannot occur.
        let (prefix_mask, prefix_value) = fold(prefix).ok_or(PatternError::PrefixNotHex)?;
        let (postfix_mask, postfix_value) = fold(postfix).ok_or(PatternError::PostfixNotHex)?;
        // Move the prefix to the top. An empty prefix needs a shift of 128,
        // which `checked_shl` rejects; its mask and value are zero anyway.
        let shift = u32::try_from((ADDRESS_HEX_LENGTH - prefix.len()) * 4).unwrap_or(0);
        let up = |x: u128| x.checked_shl(shift).unwrap_or(0);
        Ok(Self {
            mask: up(prefix_mask) | postfix_mask,
            value: up(prefix_value) | postfix_value,
        })
    }

    /// Port of matcher.go `matches`. No allocation; the fixed-size input
    /// replaces Go's length check.
    #[must_use]
    pub fn matches(&self, address: &[u8; 16]) -> bool {
        u128::from_be_bytes(*address) & self.mask == self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* generator, tests only.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn address(&mut self) -> [u8; 16] {
            let mut out = [0u8; 16];
            for chunk in out.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_be_bytes());
            }
            out
        }
    }

    fn hex(address: &[u8; 16]) -> String {
        address.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Go's definition: lower-case hex string with prefix and suffix.
    fn oracle_hex(h: &str, prefix: &str, postfix: &str) -> bool {
        h.starts_with(&prefix.to_lowercase()) && h.ends_with(&postfix.to_lowercase())
    }

    fn oracle(address: &[u8; 16], prefix: &str, postfix: &str) -> bool {
        oracle_hex(&hex(address), prefix, postfix)
    }

    fn patterns(max_len: usize) -> Vec<String> {
        let mut out = vec![String::new()];
        let mut layer = vec![String::new()];
        for _ in 0..max_len {
            layer = layer
                .iter()
                .flat_map(|p| "07af".chars().map(move |c| format!("{p}{c}")))
                .collect();
            out.extend(layer.iter().cloned());
        }
        out
    }

    // Go: TestAddressMatcherMatchesHexStringSemantics
    #[test]
    fn matches_hex_string_semantics_for_every_short_pattern() {
        let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
        let mut addresses: Vec<[u8; 16]> = (0..4096).map(|_| rng.address()).collect();
        // Addresses built from the pattern alphabet, so matches are common.
        addresses.extend((0..1024).map(|_| {
            let mut a = [0u8; 16];
            for b in &mut a {
                *b = [0x00, 0x07, 0x70, 0x77, 0xaf, 0xfa, 0xff, 0x0a][(rng.next() % 8) as usize];
            }
            a
        }));
        let hexes: Vec<String> = addresses.iter().map(hex).collect();
        let pats = patterns(3);
        let mut hits = 0u32;
        for prefix in &pats {
            for postfix in &pats {
                let Ok(m) = Matcher::new(prefix.as_bytes(), postfix.as_bytes()) else {
                    assert!(prefix.is_empty() && postfix.is_empty());
                    continue;
                };
                for (a, h) in addresses.iter().zip(&hexes) {
                    let want = h.starts_with(prefix.as_str()) && h.ends_with(postfix.as_str());
                    assert_eq!(m.matches(a), want, "prefix {prefix:?} postfix {postfix:?}");
                    hits += u32::from(want);
                }
            }
        }
        assert!(hits > 1000, "oracle never matched; the test proves nothing");
    }

    #[test]
    fn go_table_and_uppercase() {
        let address: [u8; 16] = [0xab, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0xef];
        let cases: [(&str, &str, bool); 10] = [
            ("abc", "def", true),
            ("ABC", "DEF", true),
            ("a", "", true),
            ("", "f", true),
            ("abc00000000000000000000000000def", "", true),
            ("abd", "def", false),
            ("abc", "dee", false),
            ("abc0", "", true),
            ("", "0def", true),
            ("AbC", "dEf", true),
        ];
        for (prefix, postfix, want) in cases {
            let m = Matcher::new(prefix.as_bytes(), postfix.as_bytes()).unwrap();
            assert_eq!(m.matches(&address), want, "{prefix:?} {postfix:?}");
            assert_eq!(oracle(&address, prefix, postfix), want);
        }
    }

    // Port of the basis test matcher_accepts_every_nibble_boundary.
    #[test]
    fn every_nibble_boundary_matches_and_flips() {
        let address: [u8; 16] = std::array::from_fn(|i| (i * 17) as u8);
        let h = hex(&address);
        let h = h.as_bytes();
        for left in 0..=32 {
            for right in 0..=32 - left {
                if left + right == 0 {
                    continue;
                }
                let m = Matcher::new(&h[..left], &h[32 - right..]).unwrap();
                assert!(m.matches(&address));
                for i in 0..32 {
                    let mut changed = address;
                    changed[i / 2] ^= if i % 2 == 0 { 0x10 } else { 0x01 };
                    assert_eq!(m.matches(&changed), i >= left && i < 32 - right);
                }
            }
        }
    }

    #[test]
    fn full_length_edges() {
        let address: [u8; 16] = std::array::from_fn(|i| (i * 11 + 3) as u8);
        let h = hex(&address);
        for (p, s) in [
            (&h[..], ""),
            ("", &h[..]),
            (&h[..16], &h[16..]),
            (&h[..15], &h[15..]),
        ] {
            let m = Matcher::new(p.as_bytes(), s.as_bytes()).unwrap();
            assert!(m.matches(&address));
            let mut other = address;
            other[7] ^= 0x01;
            assert!(!m.matches(&other));
        }
        let m = Matcher::new(&h.as_bytes()[..17], &h.as_bytes()[17..]).unwrap();
        assert!(m.matches(&address));
    }

    // Go: TestAddressMatcherRejectsInvalidConstruction, and REFERENCE_FACTS §5.
    #[test]
    fn rejections_use_go_messages_in_go_order() {
        let a33 = "a".repeat(33);
        let b33 = "b".repeat(33);
        let a16 = "a".repeat(16);
        let b17 = "b".repeat(17);
        let cases: [(&[u8], &[u8], &str); 14] = [
            (
                b"",
                b"",
                "at least one of --prefix or --postfix must be specified",
            ),
            (a33.as_bytes(), b"", "prefix must be 1-32 hex characters"),
            (b"", b33.as_bytes(), "postfix must be 1-32 hex characters"),
            // Length is checked before the character set, and prefix first.
            (a33.as_bytes(), b"zz", "prefix must be 1-32 hex characters"),
            (b"zz", b33.as_bytes(), "postfix must be 1-32 hex characters"),
            (
                b"xyz",
                b"",
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                b"g",
                b"",
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                b"a b",
                b"",
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                "é".as_bytes(),
                b"",
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                b"\xff",
                b"",
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                b"",
                b"g",
                "postfix must contain only hex characters [0-9a-fA-F]",
            ),
            // Prefix character set before postfix character set.
            (
                b"g",
                b"g",
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                b"a",
                "é".as_bytes(),
                "postfix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                a16.as_bytes(),
                b17.as_bytes(),
                "combined prefix and postfix length must not exceed 32 hex characters",
            ),
        ];
        for (prefix, postfix, want) in cases {
            let err = Matcher::new(prefix, postfix).unwrap_err();
            assert_eq!(err.to_string(), want);
            assert_eq!(validate_patterns(prefix, postfix).unwrap_err(), err);
        }
        // Lengths are bytes: 17 two-byte characters are 34 bytes.
        assert_eq!(
            validate_patterns("é".repeat(17).as_bytes(), b"").unwrap_err(),
            PatternError::PrefixTooLong
        );
    }

    #[test]
    fn accepts_patterns_at_the_limits() {
        assert!(validate_patterns(b"a", b"").is_ok());
        assert!(validate_patterns(b"", b"F").is_ok());
        assert!(validate_patterns("a".repeat(32).as_bytes(), b"").is_ok());
        assert!(validate_patterns("a".repeat(16).as_bytes(), "B".repeat(16).as_bytes()).is_ok());
    }
}
