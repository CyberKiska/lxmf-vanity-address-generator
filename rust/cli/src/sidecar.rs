//! The inspection text and the `<out>.txt` sidecar, in its public and
//! private-export variants.
//!
//! Port of sidecar.go `writePublicIdentityInfo` and `(*outputTarget).writeIdentityInfo`
//! (REFERENCE_FACTS section 9). Writing the file is P3-02's job; this module only builds the bytes.
//!
//! The text layout follows the basis `public_info`/`metadata`, with Go's `%q`
//! quoting (`goquote`) instead of Rust's `Debug`.

use lxmf_vanity_core::identity::{Identity, PublicIdentity};
use zeroize::{Zeroize, Zeroizing};

use crate::encode::{base32_into, base64url_into, hex_into};
use crate::goquote::quote_into;

/// Go reserves 1280 bytes for the public block, then 512 more before any
/// secret enters the buffer (`info.Grow(1280)`, `info.Grow(512)`).
const PUBLIC_CAPACITY: usize = 1280;
const PRIVATE_CAPACITY: usize = 512;

const PUBLIC_ONLY_LINE: &[u8] = b"This metadata file contains public information only.\n";
const WARNING_LINE: &[u8] = b"\nWARNING: Reversible private identity exports follow. Protect this file like the identity file.\n";
const BASE64_LABEL_LINE: &[u8] = b"Reticulum URL-safe Base64 private identity:\n  ";
const BASE32_LABEL_LINE: &[u8] = b"Reticulum Base32 private identity:\n  ";
const VERIFY_LINES: &[u8] = b"\nVerify with:\n  rnid -i <identity_file> -H lxmf.delivery\n";

/// The sidecar bytes. A private-export sidecar holds secrets, so the buffer is
/// wiped, including its unused capacity, when it is dropped.
pub(crate) struct SidecarBuf(Vec<u8>);

impl SidecarBuf {
    /// Reserves Go's 1280 bytes up front.
    pub(crate) fn new() -> Self {
        SidecarBuf(Vec::with_capacity(PUBLIC_CAPACITY))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Overwrites the whole allocation with zeros. Unlike `Vec::zeroize` this
    /// leaves the length at the capacity, so a test can read every byte.
    fn wipe(&mut self) {
        let capacity = self.0.capacity();
        // Within capacity: no reallocation, so no abandoned copy.
        self.0.resize(capacity, 0);
        self.0.as_mut_slice().zeroize();
    }
}

impl Drop for SidecarBuf {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Port of `writePublicIdentityInfo`. `file_base_name` is `filepath.Base` of the
/// file, never an absolute path: it is quoted like Go's `%q`.
pub(crate) fn write_public_identity_info(
    out: &mut Vec<u8>,
    identity: &PublicIdentity,
    file_base_name: &[u8],
) {
    out.reserve(PUBLIC_CAPACITY);
    let hex = |out: &mut Vec<u8>, bytes: &[u8]| hex_into(out, bytes);
    out.extend_from_slice(
        b"LXMF Vanity Address Identity\n============================\n\nAddress (LXMF): ",
    );
    hex(out, &identity.address);
    out.extend_from_slice(b"\nIdentity Hash:  ");
    hex(out, &identity.identity_hash);
    out.extend_from_slice(b"\nFull Specifier: <lxmf.delivery.");
    hex(out, &identity.identity_hash);
    out.push(b':');
    hex(out, &identity.address);
    out.extend_from_slice(b">\n\nPublic Key (X25519 + Ed25519):\n  X25519 Public:  ");
    hex(out, &identity.x25519_public);
    out.extend_from_slice(b"\n  Ed25519 Public: ");
    hex(out, &identity.ed25519_public);
    out.extend_from_slice(b"\n  Combined:       ");
    hex(out, &identity.x25519_public);
    hex(out, &identity.ed25519_public);
    out.extend_from_slice(b"\n\nPrivate identity file: ");
    quote_into(out, file_base_name);
    out.push(b'\n');
}

/// Port of `writeIdentityInfo`: appends the public block, then either the
/// public-only line or (with `private`) the warning and both encodings, then the
/// `Verify with:` lines. The private encodings are written straight into `out`
/// after 512 bytes were reserved, so the buffer never reallocates around a
/// secret; the 64-byte staging copy is wiped before returning.
pub(crate) fn sidecar_bytes(
    out: &mut SidecarBuf,
    identity: &PublicIdentity,
    file_base_name: &[u8],
    private: Option<&Identity>,
) {
    write_public_identity_info(&mut out.0, identity, file_base_name);
    match private {
        None => out.0.extend_from_slice(PUBLIC_ONLY_LINE),
        Some(private) => {
            out.0.reserve(PRIVATE_CAPACITY);
            let mut staging = Zeroizing::new([0u8; 64]);
            append_private_exports(&mut out.0, &mut staging, private);
        }
    }
    out.0.extend_from_slice(VERIFY_LINES);
}

/// The warning and both encodings. `out` must have room for 512 more bytes;
/// the text needs about 440. `staging` is wiped before returning.
fn append_private_exports(out: &mut Vec<u8>, staging: &mut [u8; 64], private: &Identity) {
    private.private_file_bytes(staging);
    out.extend_from_slice(WARNING_LINE);
    out.extend_from_slice(BASE64_LABEL_LINE);
    base64url_into(out, staging);
    out.push(b'\n');
    out.extend_from_slice(BASE32_LABEL_LINE);
    base32_into(out, staging);
    out.push(b'\n');
    staging.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use lxmf_vanity_core::identity::CandidateInput;

    // The golden fixture's x25519_private || ed25519_seed (public test vector,
    // REFERENCE_FACTS section 2): bytes 0x00..0x1e, 0x5f, then 0x20..0x3f.
    fn golden_private_bytes() -> [u8; 64] {
        let mut b = [0u8; 64];
        for i in 0..32u8 {
            b[usize::from(i)] = i;
            b[usize::from(32 + i)] = 0x20 + i;
        }
        b[31] = 0x5f;
        b
    }

    fn golden_identity() -> Identity {
        let mut input = CandidateInput::zeroed();
        input
            .as_mut_bytes()
            .copy_from_slice(&golden_private_bytes());
        Identity::derive(&input)
    }

    // How: the reference binary (main-5bbe76e, darwin-arm64), run as
    // `lxmf-vanity --inspect golden-public-fixture` on a 64-byte file holding
    // `golden_private_bytes()`; stdout, matching REFERENCE_FACTS section 9.
    const GOLDEN_INSPECT: &str = "LXMF Vanity Address Identity\n============================\n\nAddress (LXMF): fae321c442e3c9bdcd7a3e79d850e03c\nIdentity Hash:  aca31af0441d81dbec71e82da0b4b5f5\nFull Specifier: <lxmf.delivery.aca31af0441d81dbec71e82da0b4b5f5:fae321c442e3c9bdcd7a3e79d850e03c>\n\nPublic Key (X25519 + Ed25519):\n  X25519 Public:  8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f\n  Ed25519 Public: 29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n  Combined:       8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n\nPrivate identity file: \"golden-public-fixture\"\n";

    // How: a scratch Go 1.27.4 program that runs the same statements as
    // sidecar.go `writeIdentityInfo` (private variant) on the golden values,
    // with `base64.URLEncoding` and `base32.StdEncoding`. Its layout was also
    // compared against a real sidecar the reference binary wrote with
    // `--include-private-exports` for a throwaway identity.
    const GOLDEN_PRIVATE_SIDECAR: &str = "LXMF Vanity Address Identity\n============================\n\nAddress (LXMF): fae321c442e3c9bdcd7a3e79d850e03c\nIdentity Hash:  aca31af0441d81dbec71e82da0b4b5f5\nFull Specifier: <lxmf.delivery.aca31af0441d81dbec71e82da0b4b5f5:fae321c442e3c9bdcd7a3e79d850e03c>\n\nPublic Key (X25519 + Ed25519):\n  X25519 Public:  8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f\n  Ed25519 Public: 29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n  Combined:       8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n\nPrivate identity file: \"golden-public-fixture\"\n\nWARNING: Reversible private identity exports follow. Protect this file like the identity file.\nReticulum URL-safe Base64 private identity:\n  AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHl8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw==\nReticulum Base32 private identity:\n  AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DZPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4PY=\n\nVerify with:\n  rnid -i <identity_file> -H lxmf.delivery\n";

    fn info(name: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_public_identity_info(&mut out, &golden_identity().public(), name);
        out
    }

    #[test]
    fn inspection_text_for_the_golden_vector_equals_go() {
        let mut text = info(b"golden-public-fixture");
        text.extend_from_slice(PUBLIC_ONLY_LINE);
        let want =
            format!("{GOLDEN_INSPECT}This metadata file contains public information only.\n");
        assert_eq!(String::from_utf8(text).unwrap(), want);
    }

    // How: the reference binary's `--inspect` on files with these names in a
    // temporary directory (the "Private identity file:" line). The invalid
    // UTF-8 name cannot exist on macOS, so its expectation comes from a scratch
    // Go program printing `fmt.Sprintf("%q", "bad\xffname\xc3")`.
    #[test]
    fn file_names_are_quoted_like_go_percent_q() {
        for (name, want) in [
            (&b"with space"[..], "\"with space\""),
            (b"q\"uote", "\"q\\\"uote\""),
            (b"tab\there", "\"tab\\there\""),
            ("é".as_bytes(), "\"é\""),
            (b"back\\slash", "\"back\\\\slash\""),
            (b"nl\nx", "\"nl\\nx\""),
            ("\u{2028}x".as_bytes(), "\"\\u2028x\""),
            (b"\x7f", "\"\\x7f\""),
            (b"a\x01z", "\"a\\x01z\""),
            (b"bad\xffname\xc3", "\"bad\\xffname\\xc3\""),
        ] {
            let text = info(name);
            let line = text.rsplit(|&b| b == b'\n').nth(1).unwrap();
            assert_eq!(
                line,
                format!("Private identity file: {want}").as_bytes(),
                "name {name:?}"
            );
        }
    }

    // How: the reference binary, `lxmf-vanity --prefix a --out saved1` in a
    // temporary directory; the file `saved1.txt` it wrote (a throwaway
    // identity whose public values are kept here).
    #[test]
    fn public_sidecar_equals_go_and_holds_no_private_text() {
        let public = PublicIdentity {
            x25519_public: hex("83ba7d3ea755f5ab3417e4655b1891bc003006d977040f292a3b76e258fb5f2f"),
            ed25519_public: hex("b05b48b0b077b72fd358ef8d30805a1ffb369ca6a7c7f5569209bb5fef2ca479"),
            identity_hash: hex("2aad19d6700285b42512eca6be565d24"),
            address: hex("a22c5ba7510055133a6a5984b714ff4b"),
        };
        let mut buf = SidecarBuf::new();
        sidecar_bytes(&mut buf, &public, b"saved1", None);
        let want = "LXMF Vanity Address Identity\n============================\n\nAddress (LXMF): a22c5ba7510055133a6a5984b714ff4b\nIdentity Hash:  2aad19d6700285b42512eca6be565d24\nFull Specifier: <lxmf.delivery.2aad19d6700285b42512eca6be565d24:a22c5ba7510055133a6a5984b714ff4b>\n\nPublic Key (X25519 + Ed25519):\n  X25519 Public:  83ba7d3ea755f5ab3417e4655b1891bc003006d977040f292a3b76e258fb5f2f\n  Ed25519 Public: b05b48b0b077b72fd358ef8d30805a1ffb369ca6a7c7f5569209bb5fef2ca479\n  Combined:       83ba7d3ea755f5ab3417e4655b1891bc003006d977040f292a3b76e258fb5f2fb05b48b0b077b72fd358ef8d30805a1ffb369ca6a7c7f5569209bb5fef2ca479\n\nPrivate identity file: \"saved1\"\nThis metadata file contains public information only.\n\nVerify with:\n  rnid -i <identity_file> -H lxmf.delivery\n";
        assert_eq!(std::str::from_utf8(buf.as_bytes()).unwrap(), want);
        for needle in ["Reticulum", "WARNING", "Base64", "Base32"] {
            assert!(!want.contains(needle), "{needle}");
        }
    }

    #[test]
    fn private_sidecar_for_the_golden_vector_equals_go() {
        let mut buf = SidecarBuf::new();
        let identity = golden_identity();
        sidecar_bytes(
            &mut buf,
            &identity.public(),
            b"golden-public-fixture",
            Some(&identity),
        );
        assert_eq!(
            std::str::from_utf8(buf.as_bytes()).unwrap(),
            GOLDEN_PRIVATE_SIDECAR
        );
    }

    // verify.py `parse_metadata` splits each stripped line at the first ":" and
    // rejects a duplicate label; the private labels must have an empty value
    // and the encoding on the next line.
    #[test]
    fn each_verify_py_label_appears_exactly_once() {
        let identity = golden_identity();
        for private in [None, Some(&identity)] {
            let mut buf = SidecarBuf::new();
            sidecar_bytes(&mut buf, &identity.public(), b"x", private);
            let text = std::str::from_utf8(buf.as_bytes()).unwrap();
            let count = |label: &str| {
                text.lines()
                    .filter(|l| l.trim().split_once(':').is_some_and(|(k, _)| k == label))
                    .count()
            };
            for label in [
                "Address (LXMF)",
                "Identity Hash",
                "Full Specifier",
                "X25519 Public",
                "Ed25519 Public",
                "Combined",
            ] {
                assert_eq!(count(label), 1, "{label}");
            }
            let want = usize::from(private.is_some());
            assert_eq!(count("Reticulum URL-safe Base64 private identity"), want);
            assert_eq!(count("Reticulum Base32 private identity"), want);
            let public_only = "This metadata file contains public information only.";
            let warning = "WARNING: Reversible private identity exports follow. Protect this file like the identity file.";
            assert_eq!(text.lines().filter(|l| *l == public_only).count(), 1 - want);
            assert_eq!(text.lines().filter(|l| *l == warning).count(), want);
            assert!(text.ends_with("\nVerify with:\n  rnid -i <identity_file> -H lxmf.delivery\n"));
        }
    }

    #[test]
    fn private_encodings_have_the_documented_lengths() {
        let identity = golden_identity();
        let mut buf = SidecarBuf::new();
        sidecar_bytes(&mut buf, &identity.public(), b"x", Some(&identity));
        let text = std::str::from_utf8(buf.as_bytes()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let at = |label: &str| lines.iter().position(|l| *l == label).unwrap();
        let b64 = lines[at("Reticulum URL-safe Base64 private identity:") + 1];
        let b32 = lines[at("Reticulum Base32 private identity:") + 1];
        assert!(b64.starts_with("  ") && b32.starts_with("  "));
        assert_eq!((b64.len() - 2, b32.len() - 2), (88, 104));
    }

    #[test]
    fn private_variant_never_reallocates_the_buffer() {
        let identity = golden_identity();
        let mut buf = SidecarBuf::new();
        let capacity = buf.0.capacity();
        sidecar_bytes(
            &mut buf,
            &identity.public(),
            b"golden-public-fixture",
            Some(&identity),
        );
        assert_eq!(buf.0.capacity(), capacity);
        assert!(buf.0.len() <= PUBLIC_CAPACITY);

        // The private part needs less than the 512 bytes reserved for it.
        let mut out = Vec::with_capacity(100 + PRIVATE_CAPACITY);
        out.extend_from_slice(&[b'x'; 100]);
        let capacity = out.capacity();
        append_private_exports(&mut out, &mut [0u8; 64], &identity);
        assert_eq!(out.capacity(), capacity);
        assert!(out.len() - 100 < PRIVATE_CAPACITY);
    }

    // Test-only observation of the wipes: the staging copy of the 64 private
    // bytes, and every byte of the output allocation, are zero afterwards.
    #[test]
    fn private_staging_copy_and_output_buffer_are_wiped() {
        let identity = golden_identity();
        let mut staging = [0u8; 64];
        let mut out = Vec::with_capacity(1024);
        append_private_exports(&mut out, &mut staging, &identity);
        assert_eq!(staging, [0u8; 64]);
        assert!(out.iter().any(|&b| b != 0));

        let mut buf = SidecarBuf::new();
        sidecar_bytes(&mut buf, &identity.public(), b"x", Some(&identity));
        assert!(buf.as_bytes().windows(8).any(|w| w == b"AAECAwQF"));
        buf.wipe();
        assert_eq!(buf.0.len(), buf.0.capacity());
        assert!(buf.0.iter().all(|&b| b == 0));
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
