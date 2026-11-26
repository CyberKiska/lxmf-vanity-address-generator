//! Table-free, branch-free Base64url, Base32 and hex encoders.
//!
//! The private-export sidecar encodes secret bytes, so no lookup table and no
//! branch is indexed by secret data: every 5- or 6-bit symbol is mapped to its
//! ASCII character by arithmetic on masks. Lengths and padding depend only on
//! the input length, which is public. Output is appended to a `Vec` whose
//! capacity the caller reserved first, so encoding secrets never reallocates.
//!
//! Replaces the `data-encoding` and `hex` crates of the basis (`encode.rs` is a
//! new file; the basis called those crates in `src/output/sidecar.rs`).

use zeroize::Zeroize;

/// All-ones when `a > b`, else zero, without a branch. Both are small
/// non-negative values (symbols below 64).
#[inline(always)]
fn gt_mask(a: i32, b: i32) -> i32 {
    (b - a) >> 8
}

/// URL-safe Base64 alphabet: `A-Z a-z 0-9 - _`. `v` is below 64.
#[inline(always)]
fn base64url_char(v: u8) -> u8 {
    let v = i32::from(v);
    let mut c = v + 65; // 'A'
    c += gt_mask(v, 25) & 6; // 26..: 'a' = 97
    c -= gt_mask(v, 51) & 75; // 52..: '0' = 48
    c -= gt_mask(v, 61) & 13; // 62: '-' = 45
    c += gt_mask(v, 62) & 49; // 63: '_' = 95
    c as u8
}

/// RFC 4648 Base32 alphabet: `A-Z 2-7`. `v` is below 32.
#[inline(always)]
fn base32_char(v: u8) -> u8 {
    let v = i32::from(v);
    let c = v + 65; // 'A'
    (c - (gt_mask(v, 25) & 41)) as u8 // 26..: '2' = 50
}

/// Lowercase hex digit. `v` is below 16.
#[inline(always)]
fn hex_char(v: u8) -> u8 {
    let v = i32::from(v);
    (v + 48 + (gt_mask(v, 9) & 39)) as u8
}

/// Encodes `input` in groups of `group` bytes into `chars` symbols of `bits`
/// bits each (`group * 8 == chars * bits`), padding a short last group with `=`.
fn encode(
    input: &[u8],
    out: &mut Vec<u8>,
    group: usize,
    chars: usize,
    bits: u32,
    map: fn(u8) -> u8,
) {
    let mask = (1u64 << bits) - 1;
    for chunk in input.chunks(group) {
        let mut acc = 0u64;
        for i in 0..group {
            acc = (acc << 8) | u64::from(chunk.get(i).copied().unwrap_or(0));
        }
        let used = (chunk.len() * 8).div_ceil(bits as usize);
        for j in 0..chars {
            let shift = bits * (chars - 1 - j) as u32;
            if j < used {
                out.push(map(((acc >> shift) & mask) as u8));
            } else {
                out.push(b'=');
            }
        }
        acc.zeroize();
    }
}

/// URL-safe Base64 with padding (Go `base64.URLEncoding`).
pub(crate) fn base64url_into(out: &mut Vec<u8>, input: &[u8]) {
    encode(input, out, 3, 4, 6, base64url_char);
}

/// Standard Base32 with padding (Go `base32.StdEncoding`).
pub(crate) fn base32_into(out: &mut Vec<u8>, input: &[u8]) {
    encode(input, out, 5, 8, 5, base32_char);
}

/// Lowercase hex (Go `hex.EncodeToString`), for public data.
pub(crate) fn hex_into(out: &mut Vec<u8>, input: &[u8]) {
    for &b in input {
        out.push(hex_char(b >> 4));
        out.push(hex_char(b & 0xF));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const HEX: &[u8] = b"0123456789abcdef";

    fn b64(input: &[u8]) -> String {
        let mut out = Vec::new();
        base64url_into(&mut out, input);
        String::from_utf8(out).unwrap()
    }

    fn b32(input: &[u8]) -> String {
        let mut out = Vec::new();
        base32_into(&mut out, input);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn symbol_maps_equal_the_alphabets_for_every_value() {
        for (v, &c) in B64URL.iter().enumerate() {
            assert_eq!(base64url_char(v as u8), c, "base64url symbol {v}");
        }
        for (v, &c) in B32.iter().enumerate() {
            assert_eq!(base32_char(v as u8), c, "base32 symbol {v}");
        }
        for (v, &c) in HEX.iter().enumerate() {
            assert_eq!(hex_char(v as u8), c, "hex digit {v}");
        }
    }

    // RFC 4648 section 10 test vectors (the Base64 ones are alphabet-independent).
    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64(input), want);
        }
    }

    #[test]
    fn base64_uses_the_url_safe_alphabet() {
        // Standard Base64 of these bytes is "+/8=" and "+/+/".
        assert_eq!(b64(&[0xfb, 0xff]), "-_8=");
        assert_eq!(b64(&[0xfb, 0xff, 0xbf]), "-_-_");
    }

    #[test]
    fn base32_matches_the_rfc_4648_vectors() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "MY======"),
            (b"fo", "MZXQ===="),
            (b"foo", "MZXW6==="),
            (b"foob", "MZXW6YQ="),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI======"),
        ] {
            assert_eq!(b32(input), want);
        }
    }

    #[test]
    fn hex_is_lowercase() {
        let mut out = Vec::new();
        hex_into(&mut out, &[0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(out, b"000fa5ff");
    }

    // Reference decoders written for the test: look-up by alphabet position.
    fn decode(text: &str, alphabet: &[u8], bits: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let (mut acc, mut have) = (0u32, 0u32);
        for c in text.bytes().take_while(|&c| c != b'=') {
            acc = (acc << bits) | alphabet.iter().position(|&a| a == c).unwrap() as u32;
            have += bits;
            if have >= 8 {
                have -= 8;
                out.push((acc >> have) as u8);
                acc &= (1 << have) - 1;
            }
        }
        out
    }

    #[test]
    fn sixty_four_byte_input_round_trips_with_the_documented_lengths() {
        let input: Vec<u8> = (0..64u32).map(|i| (i * 37 + 11) as u8).collect();
        let (e64, e32) = (b64(&input), b32(&input));
        assert_eq!((e64.len(), e32.len()), (88, 104));
        // 64 = 21 * 3 + 1 bytes: two symbols and "==" in the last group.
        assert!(e64.ends_with("==") && !e64.ends_with("==="));
        assert!(e32.ends_with('=') && !e32.ends_with("=="));
        assert_eq!(decode(&e64, B64URL, 6), input);
        assert_eq!(decode(&e32, B32, 5), input);
    }

    #[test]
    fn encoding_into_reserved_capacity_does_not_reallocate() {
        let mut out = Vec::with_capacity(88 + 104);
        let cap = out.capacity();
        base64url_into(&mut out, &[0xAB; 64]);
        base32_into(&mut out, &[0xCD; 64]);
        assert_eq!((out.len(), out.capacity()), (192, cap));
    }
}
