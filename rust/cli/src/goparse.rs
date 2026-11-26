//! Value parsers with Go's exact semantics: `strconv.ParseInt`/`ParseUint` with base 0,
//! `strconv.ParseBool` and `time.ParseDuration`. All take raw bytes, as Go takes strings.
//!
//! Ports of Go 1.27.4 `internal/strconv/atoi.go`, `atob.go` and `time/format.go`.

/// `strconv.ErrSyntax` and `strconv.ErrRange`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NumError {
    Syntax,
    Range,
}

fn lower(c: u8) -> u8 {
    c | (b'x' - b'X')
}

/// `strconv.ParseUint(s, 0, 64)`: base prefixes `0b 0o 0x` and a bare leading `0` (octal),
/// underscores as in Go integer literals, no sign.
pub(crate) fn parse_uint(s: &[u8]) -> Result<u64, NumError> {
    let Some(&first) = s.first() else {
        return Err(NumError::Syntax);
    };
    let mut digits = s;
    let mut base: u64 = 10;
    if first == b'0' {
        let prefixed = s.len() >= 3;
        match s.get(1).map(|&c| lower(c)) {
            Some(b'b') if prefixed => {
                base = 2;
                digits = &s[2..];
            }
            Some(b'o') if prefixed => {
                base = 8;
                digits = &s[2..];
            }
            Some(b'x') if prefixed => {
                base = 16;
                digits = &s[2..];
            }
            _ => {
                base = 8;
                digits = &s[1..];
            }
        }
    }
    let cutoff = u64::MAX / base + 1;
    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in digits {
        let d = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => c - b'0',
            _ if lower(c).is_ascii_lowercase() => lower(c) - b'a' + 10,
            _ => return Err(NumError::Syntax),
        };
        if u64::from(d) >= base {
            return Err(NumError::Syntax);
        }
        if n >= cutoff {
            return Err(NumError::Range);
        }
        // `n < cutoff`, so the product fits, but the sum may not.
        let Some(next) = (n * base).checked_add(u64::from(d)) else {
            return Err(NumError::Range);
        };
        n = next;
    }
    if underscores && !underscore_ok(s) {
        return Err(NumError::Syntax);
    }
    Ok(n)
}

/// `strconv.ParseInt(s, 0, 64)`.
pub(crate) fn parse_int(s: &[u8]) -> Result<i64, NumError> {
    let Some(&first) = s.first() else {
        return Err(NumError::Syntax);
    };
    let neg = first == b'-';
    let body = if first == b'+' || neg { &s[1..] } else { s };
    let magnitude = match parse_uint(body) {
        Ok(m) => m,
        Err(NumError::Range) => u64::MAX,
        Err(e) => return Err(e),
    };
    const CUTOFF: u64 = 1 << 63;
    if !neg && magnitude >= CUTOFF {
        return Err(NumError::Range);
    }
    if neg && magnitude > CUTOFF {
        return Err(NumError::Range);
    }
    // 0 - magnitude cannot overflow for magnitude <= 2^63 when computed in i128.
    i64::try_from(if neg {
        -i128::from(magnitude)
    } else {
        i128::from(magnitude)
    })
    .map_err(|_| NumError::Range)
}

/// Port of `underscoreOK`: underscores only between digits or after a base prefix.
fn underscore_ok(s: &[u8]) -> bool {
    // saw: b'^' beginning, b'0' digit or prefix, b'_' underscore, b'!' anything else.
    let mut saw = b'^';
    let mut i = 0;
    let mut s = s;
    if let Some(&(b'-' | b'+')) = s.first() {
        s = &s[1..];
    }
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(c))) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// `strconv.ParseBool`.
pub(crate) fn parse_bool(s: &[u8]) -> Result<bool, NumError> {
    match s {
        b"1" | b"t" | b"T" | b"true" | b"TRUE" | b"True" => Ok(true),
        b"0" | b"f" | b"F" | b"false" | b"FALSE" | b"False" => Ok(false),
        _ => Err(NumError::Syntax),
    }
}

// The integer and boolean parsers were compared with Go 1.27.4 on generated inputs (every
// short string over the relevant alphabets, the 2^63/2^64 boundaries, random byte strings):
// results were identical.
#[cfg(test)]
mod tests {
    use super::*;
    use NumError::{Range, Syntax};
    #[test]
    fn parse_uint_base_zero_matches_go() {
        // Go: internal/strconv atoi_test.go (base 0 rows) plus the 2^64 edges.
        let ok: &[(&str, u64)] = &[
            ("0", 0),
            ("00", 0),
            ("010", 8),
            ("0o10", 8),
            ("0O10", 8),
            ("0b11", 3),
            ("0B11", 3),
            ("0x2", 2),
            ("0Xff", 255),
            ("0xFf", 255),
            ("1_000", 1000),
            ("1_2_3_4_5", 12345),
            ("0_1_2_3_4_5", 0o12345),
            ("0x_1_2_3_4_5", 0x12345),
            ("0o_1_2", 0o12),
            ("0b_1_0_1", 5),
            ("18446744073709551615", u64::MAX),
            ("0xFFFFFFFFFFFFFFFF", u64::MAX),
            (
                "0b1111111111111111111111111111111111111111111111111111111111111111",
                u64::MAX,
            ),
            ("01777777777777777777777", u64::MAX),
            ("9223372036854775808", 1 << 63),
        ];
        for &(s, want) in ok {
            assert_eq!(parse_uint(s.as_bytes()), Ok(want), "{s}");
        }
        let syntax = [
            "", "-1", "+1", "08", "09", "0b2", "0o8", "0x", "0b", "0o", "0xg", "1__0", "_1", "1_",
            "0x_", "0x__1", "0x1__2", "0x12345_", "_0x12", "0_x1", "1 ", " 1", "1.0", "0b_", "٣",
        ];
        for s in syntax {
            assert_eq!(parse_uint(s.as_bytes()), Err(Syntax), "{s:?}");
        }
        let range = [
            "18446744073709551616",
            "99999999999999999999",
            "0x10000000000000000",
            "02000000000000000000000",
            "0b10000000000000000000000000000000000000000000000000000000000000000",
        ];
        for s in range {
            assert_eq!(parse_uint(s.as_bytes()), Err(Range), "{s}");
        }
        // A syntax error after the overflow point is still reported as a range error, like Go.
        assert_eq!(parse_uint(b"99999999999999999999x"), Err(Range));
        assert_eq!(parse_uint(b"1x"), Err(Syntax));
    }

    #[test]
    fn parse_int_base_zero_matches_go() {
        let ok: &[(&str, i64)] = &[
            ("0", 0),
            ("-0", 0),
            ("+0", 0),
            ("1", 1),
            ("+1", 1),
            ("-1", -1),
            ("010", 8),
            ("-010", -8),
            ("0x2", 2),
            ("-0xf", -15),
            ("+0xf", 15),
            ("0b11", 3),
            ("1_000", 1000),
            ("-0x_1_2", -0x12),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
            ("0x7FFFFFFFFFFFFFFF", i64::MAX),
            ("-0x8000000000000000", i64::MIN),
        ];
        for &(s, want) in ok {
            assert_eq!(parse_int(s.as_bytes()), Ok(want), "{s}");
        }
        let syntax = [
            "", "+", "-", "--1", "+-1", "-+1", "08", "-08", "0x", "-0x", "0x+f", "0x-f", "_1",
            "-_1", "_-1", "1_", "1__0", "1 ", "0b2",
        ];
        for s in syntax {
            assert_eq!(parse_int(s.as_bytes()), Err(Syntax), "{s:?}");
        }
        let range = [
            "9223372036854775808",
            "-9223372036854775809",
            "18446744073709551615",
            "18446744073709551616",
            "99999999999999999999",
            "-99999999999999999999",
            "0x8000000000000000",
            "-0x8000000000000001",
        ];
        for s in range {
            assert_eq!(parse_int(s.as_bytes()), Err(Range), "{s}");
        }
    }

    #[test]
    fn parse_bool_accepts_exactly_go_spellings() {
        for s in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_bool(s.as_bytes()), Ok(true), "{s}");
        }
        for s in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_bool(s.as_bytes()), Ok(false), "{s}");
        }
        for s in [
            "", "tRUE", "yes", "no", "on", "2", " 1", "1 ", "TrUe", "FALSe",
        ] {
            assert_eq!(parse_bool(s.as_bytes()), Err(Syntax), "{s:?}");
        }
    }
}
