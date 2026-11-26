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
