//! Hand-written JSON primitives, byte-identical to Go 1.27.4 `encoding/json`
//! (decision O-1: no `serde`). The public result is the only JSON this tool
//! writes, so only the pieces it needs exist: strings, `u64` and `f64`.

use crate::encode::hex_into;

/// `elapsed_seconds` was NaN or infinite. Go's `json.Marshal` fails with
/// `UnsupportedValueError`; the value cannot occur (a duration is finite).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NonFinite;

impl std::fmt::Display for NonFinite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("json: unsupported value: NaN or infinity")
    }
}

/// Appends `s` as a JSON string the way Go's default encoder does (HTML
/// escaping on):
/// - `\b \f \n \r \t` use short escapes, other bytes below 0x20 become `\u00xx`;
/// - `"` and `\` are escaped, `<`, `>` and `&` become `<`, `>`, `&`;
/// - U+2028 and U+2029 are escaped; `/`, DEL and other non-ASCII stay raw;
/// - every invalid UTF-8 byte becomes one raw U+FFFD, so a truncated sequence
///   gives one per byte (`String::from_utf8_lossy` would give one in total).
pub(crate) fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    let mut rest = s;
    while !rest.is_empty() {
        let (valid, invalid) = match std::str::from_utf8(rest) {
            Ok(text) => (text, 0),
            Err(e) => {
                let (head, _) = rest.split_at(e.valid_up_to());
                // Reslicing at a validated boundary: this parse cannot fail.
                let text = std::str::from_utf8(head).unwrap_or_default();
                (text, e.error_len().unwrap_or(rest.len() - head.len()))
            }
        };
        push_valid(out, valid);
        for _ in 0..invalid {
            out.extend_from_slice("\u{FFFD}".as_bytes());
        }
        rest = &rest[valid.len() + invalid..];
    }
    out.push(b'"');
}

fn push_valid(out: &mut Vec<u8>, text: &str) {
    for c in text.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '<' | '>' | '&' | '\0'..='\u{1f}' => {
                out.extend_from_slice(b"\\u00");
                hex_into(out, &[c as u8]);
            }
            '\u{2028}' => out.extend_from_slice(b"\\u2028"),
            '\u{2029}' => out.extend_from_slice(b"\\u2029"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

/// Appends `n` in decimal.
pub(crate) fn push_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(n.to_string().as_bytes());
}

/// Appends `x` as Go's encoder does: the shortest round-trip decimal, in the
/// exponent form (no padding, `+` for positive exponents) when |x| < 1e-6 or
/// |x| >= 1e21. Zero is `0`. Port of `encoding/json` `floatEncoder`.
pub(crate) fn push_f64(out: &mut Vec<u8>, x: f64) -> Result<(), NonFinite> {
    if !x.is_finite() {
        return Err(NonFinite);
    }
    let abs = x.abs();
    let text = if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        // Rust's `{:e}` prints `1e21` and `9.99e-7`; Go wants `1e+21`.
        let text = format!("{x:e}");
        match text.split_once('e') {
            Some((mantissa, exp)) if !exp.starts_with('-') => format!("{mantissa}e+{exp}"),
            _ => text,
        }
    } else {
        // `{}` never uses an exponent, and prints whole values without ".0".
        format!("{x}")
    };
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_string(&mut out, input);
        out
    }

    fn f(x: f64) -> String {
        let mut out = Vec::new();
        push_f64(&mut out, x).unwrap();
        String::from_utf8(out).unwrap()
    }

    // How: scratch Go 1.27.4 program calling `json.Marshal(string)`, the same
    // toolchain that built the reference binary; the invalid-byte and U+2028
    // cases were also observed in the binary's `--json --inspect <missing path>`
    // error text (raw U+FFFD, ` `, `<`, raw DEL and `/`).
    #[test]
    fn strings_escape_exactly_like_go() {
        for (input, want) in [
            (&b"plain"[..], &b"\"plain\""[..]),
            (b"a/b\x7f", b"\"a/b\x7f\""),
            (
                b"\x00\x01\x08\x0c\n\r\t\x1f",
                b"\"\\u0000\\u0001\\b\\f\\n\\r\\t\\u001f\"",
            ),
            (b"\"\\", b"\"\\\"\\\\\""),
            (b"<>&", b"\"\\u003c\\u003e\\u0026\""),
            ("\u{2028}\u{2029}".as_bytes(), b"\"\\u2028\\u2029\""),
            ("é€😀".as_bytes(), "\"é€😀\"".as_bytes()),
            (b"", b"\"\""),
        ] {
            assert_eq!(s(input), want, "input {input:?}");
        }
    }

    #[test]
    fn each_invalid_byte_becomes_one_raw_replacement_character() {
        let r = "\u{FFFD}";
        for (input, want) in [
            (&b"\xffa\xc3"[..], format!("\"{r}a{r}\"")),
            // Truncated 3-byte sequence: two bytes, two replacements.
            (b"\xe2\x82", format!("\"{r}{r}\"")),
            (b"\xf0\x9f\x98", format!("\"{r}{r}{r}\"")),
            // A UTF-16 surrogate encoded in UTF-8 is three invalid bytes.
            (b"\xed\xa0\x80", format!("\"{r}{r}{r}\"")),
            // Overlong form and out-of-range lead byte.
            (b"\xc0\x80", format!("\"{r}{r}\"")),
            (b"\xf4\x90\x80\x80", format!("\"{r}{r}{r}{r}\"")),
            // A truncated sequence followed by valid text.
            (b"\xe2\x82a", format!("\"{r}{r}a\"")),
        ] {
            assert_eq!(s(input), want.as_bytes(), "input {input:?}");
        }
    }

    // How: scratch Go 1.27.4 program calling `json.Marshal(float64)`; the
    // task's table plus 1.5e300 and 5e-324.
    #[test]
    fn floats_format_exactly_like_go() {
        for (x, want) in [
            (0.0, "0"),
            (1.0, "1"),
            (0.5, "0.5"),
            (0.000001, "0.000001"),
            (9.99e-7, "9.99e-7"),
            (1e-7, "1e-7"),
            (123456.789, "123456.789"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (0.013250959, "0.013250959"),
            (1.5e300, "1.5e+300"),
            (5e-324, "5e-324"),
            (100.0, "100"),
            (1e6, "1000000"),
            (12345678901234567890.0, "12345678901234567000"),
        ] {
            assert_eq!(f(x), want, "value {x:e}");
        }
    }

    #[test]
    fn non_finite_floats_are_an_error_not_a_panic() {
        for x in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut out = Vec::new();
            assert_eq!(push_f64(&mut out, x), Err(NonFinite));
            assert!(out.is_empty());
        }
    }

    #[test]
    fn integers_are_plain_decimals() {
        let mut out = Vec::new();
        push_u64(&mut out, u64::MAX);
        assert_eq!(out, b"18446744073709551615");
    }
}
