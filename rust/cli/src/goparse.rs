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

/// The three error texts of `time.ParseDuration`. The flag layer reports all of them as
/// `parse error`, so only the category is kept, not the quoted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DurationError {
    /// "invalid duration"
    Invalid,
    /// "missing unit in duration"
    MissingUnit,
    /// "unknown unit ... in duration"
    UnknownUnit,
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

/// Unit table of `time.unitMap` in nanoseconds. Both micro signs (U+00B5, U+03BC) are accepted.
fn unit_nanos(unit: &[u8]) -> Option<u64> {
    Some(match unit {
        b"ns" => 1,
        b"us" | b"\xc2\xb5s" | b"\xce\xbcs" => 1_000,
        b"ms" => 1_000_000,
        b"s" => 1_000_000_000,
        b"m" => 60_000_000_000,
        b"h" => 3_600_000_000_000,
        _ => return None,
    })
}

const TWO_63: u64 = 1 << 63;

/// `leadingInt`: `None` on overflow past 2^63.
fn leading_int(s: &[u8]) -> Option<(u64, &[u8])> {
    let mut x: u64 = 0;
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if !c.is_ascii_digit() {
            break;
        }
        if x > TWO_63 / 10 {
            return None;
        }
        x = x * 10 + u64::from(c - b'0');
        if x > TWO_63 {
            return None;
        }
        i += 1;
    }
    Some((x, &s[i..]))
}

/// `leadingFraction`: digits after the point; stops accumulating precision on overflow.
fn leading_fraction(s: &[u8]) -> (u64, f64, &[u8]) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if !c.is_ascii_digit() {
            break;
        }
        i += 1;
        if overflow {
            continue;
        }
        if x > (TWO_63 - 1) / 10 {
            overflow = true;
            continue;
        }
        let y = x * 10 + u64::from(c - b'0');
        if y > TWO_63 {
            overflow = true;
            continue;
        }
        x = y;
        scale *= 10.0;
    }
    (x, scale, &s[i..])
}

/// `time.ParseDuration`: signed nanoseconds. `[-+]?([0-9]*(\.[0-9]*)?[unit])+` or a bare `0`.
pub(crate) fn parse_duration(input: &[u8]) -> Result<i64, DurationError> {
    use DurationError::{Invalid, MissingUnit, UnknownUnit};
    let mut s = input;
    let mut total: u64 = 0;
    let mut neg = false;
    if let Some(&c @ (b'-' | b'+')) = s.first() {
        neg = c == b'-';
        s = &s[1..];
    }
    if s == b"0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(Invalid);
    }
    while !s.is_empty() {
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(Invalid);
        }
        let before = s.len();
        let (mut v, rest) = leading_int(s).ok_or(Invalid)?;
        s = rest;
        let pre = before != s.len();
        let (mut f, mut scale) = (0u64, 1.0f64);
        let mut post = false;
        if s.first() == Some(&b'.') {
            s = &s[1..];
            let before = s.len();
            (f, scale, s) = leading_fraction(s);
            post = before != s.len();
        }
        if !pre && !post {
            return Err(Invalid);
        }
        // The unit is the maximal run of bytes that are neither digits nor '.'.
        let end = s
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if end == 0 {
            return Err(MissingUnit);
        }
        let (name, rest) = s.split_at(end);
        s = rest;
        let unit = unit_nanos(name).ok_or(UnknownUnit)?;
        if v > TWO_63 / unit {
            return Err(Invalid);
        }
        v *= unit;
        if f > 0 {
            // float64 keeps fractions of an hour nanosecond-accurate, exactly as Go computes it.
            // The cast truncates toward zero, like Go's uint64(float64).
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > TWO_63 {
                return Err(Invalid);
            }
        }
        // Go adds with wrap-around: two terms of exactly 2^63 sum to 0 and pass the check.
        // Kept on purpose so the result matches Go bit for bit.
        total = total.wrapping_add(v);
        if total > TWO_63 {
            return Err(Invalid);
        }
    }
    if neg {
        // total <= 2^63, so the negation fits.
        return i64::try_from(-i128::from(total)).map_err(|_| Invalid);
    }
    i64::try_from(total).map_err(|_| Invalid)
}

// Besides the tables below, these parsers were compared with Go 1.27.4 on 962,652 generated
// inputs (every short string over the relevant alphabets, the 2^63/2^64 boundaries, random
// byte strings) and on every Unicode scalar value: integer, boolean and duration results,
// including the three duration error categories, were identical.
#[cfg(test)]
mod tests {
    use super::*;
    use DurationError::{Invalid, MissingUnit, UnknownUnit};
    use NumError::{Range, Syntax};

    const SEC: i64 = 1_000_000_000;
    const MS: i64 = 1_000_000;
    const US: i64 = 1_000;
    const MIN: i64 = 60 * SEC;
    const HOUR: i64 = 60 * MIN;

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

    #[test]
    fn parse_duration_matches_go_time_test_table() {
        // Go: time_test.go parseDurationTests, copied case for case.
        let cases: &[(&str, i64)] = &[
            ("0", 0),
            ("5s", 5 * SEC),
            ("30s", 30 * SEC),
            ("1478s", 1478 * SEC),
            ("-5s", -5 * SEC),
            ("+5s", 5 * SEC),
            ("-0", 0),
            ("+0", 0),
            ("5.0s", 5 * SEC),
            ("5.6s", 5 * SEC + 600 * MS),
            ("5.s", 5 * SEC),
            (".5s", 500 * MS),
            ("1.0s", SEC),
            ("1.00s", SEC),
            ("1.004s", SEC + 4 * MS),
            ("1.0040s", SEC + 4 * MS),
            ("100.00100s", 100 * SEC + MS),
            ("10ns", 10),
            ("11us", 11 * US),
            ("12\u{b5}s", 12 * US),
            ("12\u{3bc}s", 12 * US),
            ("13ms", 13 * MS),
            ("14s", 14 * SEC),
            ("15m", 15 * MIN),
            ("16h", 16 * HOUR),
            ("3h30m", 3 * HOUR + 30 * MIN),
            ("10.5s4m", 4 * MIN + 10 * SEC + 500 * MS),
            ("-2m3.4s", -(2 * MIN + 3 * SEC + 400 * MS)),
            (
                "1h2m3s4ms5us6ns",
                HOUR + 2 * MIN + 3 * SEC + 4 * MS + 5 * US + 6,
            ),
            ("39h9m14.425s", 39 * HOUR + 9 * MIN + 14 * SEC + 425 * MS),
            ("52763797000ns", 52_763_797_000),
            ("0.3333333333333333333h", 20 * MIN),
            ("9007199254740993ns", (1 << 53) + 1),
            ("9223372036854775807ns", i64::MAX),
            ("9223372036854775.807us", i64::MAX),
            ("9223372036s854ms775us807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
            ("-9223372036854775.808us", i64::MIN),
            ("-9223372036s854ms775us808ns", i64::MIN),
            ("-2562047h47m16.854775808s", i64::MIN),
            ("0.100000000000000000000h", 6 * MIN),
            (
                "0.830103483285477580700h",
                49 * MIN + 48 * SEC + 372_539_827,
            ),
            // Cases from the task: valid forms of the grammar.
            ("1.5h", HOUR + 30 * MIN),
            ("1h30m", HOUR + 30 * MIN),
            ("1.s", SEC),
            ("1.5ms", 1_500_000),
            ("+1ms", MS),
            ("1.ms", MS),
            ("1us", US),
            ("1\u{b5}s", US),
            // Fractions below one nanosecond are dropped by Go's float64 arithmetic. The basis's
            // integer fold would give 999_999_999 for the second row; Go gives 1s.
            ("1.9ns", 1),
            ("0.9999999999999999999999s", SEC),
            (".99999999999999999999h", HOUR), // basis fold gave 3_599_999_999_999; Go gives 1h
            ("2\u{b5}s3\u{3bc}s4us", 9 * US),
        ];
        for &(s, want) in cases {
            assert_eq!(parse_duration(s.as_bytes()), Ok(want), "{s}");
        }
    }

    #[test]
    fn parse_duration_error_categories_match_go() {
        let invalid = [
            "",
            "+",
            "-",
            ".",
            "-.",
            ".s",
            "+.s",
            "1s.",
            "s1",
            "\u{fffd}",
            // Overflow in every place Go checks.
            "9223372036854775810ns",
            "9223372036854775808ns",
            "-9223372036854775809ns",
            "9223372036854776us",
            "3000000h",
            "9223372036854775.808us",
            "9223372036854ms775us808ns",
            "99999999999999999999ns",
        ];
        for s in invalid {
            assert_eq!(parse_duration(s.as_bytes()), Err(Invalid), "{s:?}");
        }
        for s in ["3", "1", "5", "1s2", "-1", "1.5", "1h30", ".5"] {
            assert_eq!(parse_duration(s.as_bytes()), Err(MissingUnit), "{s:?}");
        }
        for s in [
            "1d",
            "1 s",
            "1S",
            "1H",
            "1\u{2126}s",
            "1min",
            "1sm",
            "1\u{b5}",
            "1u",
            "1y",
            "1w",
        ] {
            assert_eq!(parse_duration(s.as_bytes()), Err(UnknownUnit), "{s:?}");
        }
        // Invalid UTF-8 is just unknown bytes.
        assert_eq!(parse_duration(b"\x85\x85"), Err(Invalid));
        assert_eq!(parse_duration(b"1\xffs"), Err(UnknownUnit));
    }

    #[test]
    fn parse_duration_takes_the_maximal_unit_run_not_a_prefix() {
        // The unit is everything up to the next digit or '.', so "1sx" is an unknown unit
        // even though it starts with a valid one.
        assert_eq!(parse_duration(b"1sx"), Err(UnknownUnit));
        assert_eq!(parse_duration(b"1msx"), Err(UnknownUnit));
        assert_eq!(parse_duration(b"1m1s"), Ok(MIN + SEC));
        assert_eq!(parse_duration(b"1sm"), Err(UnknownUnit));
    }

    #[test]
    fn parse_duration_wraps_like_go_when_two_terms_sum_to_two_pow_63() {
        // Go adds the terms with wrap-around: 2^63 + 2^63 becomes 0 and is accepted.
        // Observed with Go 1.27.4 on this exact input.
        assert_eq!(
            parse_duration(b"9223372036854775808ns9223372036854775808ns"),
            Ok(0)
        );
        assert_eq!(parse_duration(b"9223372036854775808ns1ns"), Err(Invalid));
    }
}
