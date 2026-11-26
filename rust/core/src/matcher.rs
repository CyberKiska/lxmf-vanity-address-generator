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
