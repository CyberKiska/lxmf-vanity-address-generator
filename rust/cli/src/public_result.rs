//! The public JSON result and the final write of a run's output.
//!
//! Port of result.go: `publicResult`, `newPublicResult`, `(*publicResult).identity`
//! and `writeResult`. Field order, omission rules and encoding equal Go's
//! `json.Marshal` (REFERENCE_FACTS section 8); the writer lives in `jsonw.rs`.
//!
//! Everything here is public data. The result never holds a private key.
//!
//! Field order and the identity grouping follow the basis `ResultInfo`, which
//! matched Go.

use std::borrow::Cow;
use std::io::{self, Write};

use lxmf_vanity_core::identity::PublicIdentity;

use crate::encode::hex_into;
use crate::jsonw::{self, NonFinite};
use crate::version::version_string;

/// A file path as bytes, with the platform that produced it.
///
/// Go turns a path into a string before printing it. On Unix that string holds
/// the raw bytes, and the JSON writer replaces each invalid byte. On Windows
/// the path is UTF-16, and Go's conversion replaces each unpaired surrogate by
/// one U+FFFD; Rust's `OsStr` holds it as WTF-8, where an unpaired surrogate is
/// a three-byte `ED A0..BF 80..BF` sequence that would otherwise count as
/// three invalid bytes. `windows` selects that conversion (REFERENCE_FACTS section 8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathBytes {
    bytes: Vec<u8>,
    windows: bool,
}

impl PathBytes {
    /// `bytes` are `OsStr::as_encoded_bytes()` of the path; `windows` is
    /// `cfg!(windows)` for a real path.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "file lists arrive with the save path (P3-05)")
    )]
    pub(crate) fn new(bytes: Vec<u8>, windows: bool) -> Self {
        PathBytes { bytes, windows }
    }

    /// The bytes of the Go string for this path: what `%s` prints, and what the
    /// JSON writer then validates.
    pub(crate) fn go_bytes(&self) -> Cow<'_, [u8]> {
        if !self.windows || !self.bytes.contains(&0xED) {
            return Cow::Borrowed(&self.bytes);
        }
        let mut out = Vec::with_capacity(self.bytes.len());
        let mut rest = self.bytes.as_slice();
        while let Some((&first, tail)) = rest.split_first() {
            if let [0xED, 0xA0..=0xBF, 0x80..=0xBF, ..] = rest {
                out.extend_from_slice("\u{FFFD}".as_bytes());
                rest = &rest[3..];
            } else {
                out.push(first);
                rest = tail;
            }
        }
        Cow::Owned(out)
    }
}

/// Go's `publicResult`.
#[derive(Debug)]
pub(crate) struct PublicResult {
    pub status: &'static str,
    /// The five identity fields (`address` .. `public_key`); `None` omits them.
    pub public: Option<PublicIdentity>,
    pub verified_files: Vec<PathBytes>,
    pub unverified_files: Vec<PathBytes>,
    /// Go strings: arbitrary bytes, validated when written.
    pub deviations: Vec<Vec<u8>>,
    pub notices: Vec<Vec<u8>>,
    pub attempts: u64,
    pub elapsed_seconds: f64,
    /// The parsed `--generator` value, empty or unvalidated for `--version`.
    pub generator: Vec<u8>,
    pub version: String,
    /// Omitted when empty.
    pub error: Vec<u8>,
}

impl PublicResult {
    /// Port of `newPublicResult`: status `failed`, empty arrays.
    pub(crate) fn new(generator: &[u8]) -> Self {
        PublicResult {
            status: "failed",
            public: None,
            verified_files: Vec::new(),
            unverified_files: Vec::new(),
            deviations: Vec::new(),
            notices: Vec::new(),
            attempts: 0,
            elapsed_seconds: 0.0,
            generator: generator.to_vec(),
            version: version_string().to_owned(),
            error: Vec::new(),
        }
    }

    /// Port of `(*publicResult).identity`.
    pub(crate) fn identity(&mut self, identity: &PublicIdentity) {
        self.public = Some(*identity);
    }

    /// `json.Marshal(result)` followed by `\n`.
    pub(crate) fn to_json(&self) -> Result<Vec<u8>, NonFinite> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"{\"status\":");
        jsonw::push_string(&mut out, self.status.as_bytes());
        if let Some(id) = &self.public {
            for (key, value) in [
                ("address", &id.address[..]),
                ("identity_hash", &id.identity_hash[..]),
                ("x25519_public", &id.x25519_public[..]),
                ("ed25519_public", &id.ed25519_public[..]),
            ] {
                push_hex_field(&mut out, key, &[value]);
            }
            push_hex_field(
                &mut out,
                "public_key",
                &[&id.x25519_public[..], &id.ed25519_public[..]],
            );
        }
        out.extend_from_slice(b",\"verified_files\":");
        push_array(
            &mut out,
            self.verified_files.iter().map(PathBytes::go_bytes),
        );
        out.extend_from_slice(b",\"unverified_files\":");
        push_array(
            &mut out,
            self.unverified_files.iter().map(PathBytes::go_bytes),
        );
        out.extend_from_slice(b",\"deviations\":");
        push_array(
            &mut out,
            self.deviations.iter().map(|s| Cow::Borrowed(&s[..])),
        );
        out.extend_from_slice(b",\"notices\":");
        push_array(&mut out, self.notices.iter().map(|s| Cow::Borrowed(&s[..])));
        out.extend_from_slice(b",\"attempts\":");
        jsonw::push_u64(&mut out, self.attempts);
        out.extend_from_slice(b",\"elapsed_seconds\":");
        jsonw::push_f64(&mut out, self.elapsed_seconds)?;
        out.extend_from_slice(b",\"generator\":");
        jsonw::push_string(&mut out, &self.generator);
        out.extend_from_slice(b",\"version\":");
        jsonw::push_string(&mut out, self.version.as_bytes());
        if !self.error.is_empty() {
            out.extend_from_slice(b",\"error\":");
            jsonw::push_string(&mut out, &self.error);
        }
        out.extend_from_slice(b"}\n");
        Ok(out)
    }
}

/// `,"key":"<hex of the parts, joined>"`.
fn push_hex_field(out: &mut Vec<u8>, key: &str, parts: &[&[u8]]) {
    out.extend_from_slice(b",\"");
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b"\":\"");
    for part in parts {
        hex_into(out, part);
    }
    out.push(b'"');
}

/// `[]` or `["a","b"]`: an array is always present.
fn push_array<'a>(out: &mut Vec<u8>, items: impl Iterator<Item = Cow<'a, [u8]>>) {
    out.push(b'[');
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(b',');
        }
        jsonw::push_string(out, &item);
    }
    out.push(b']');
}

/// Port of `writeResult`: the JSON result when `result` is `Some`, else `text`.
///
/// Go makes one `Write` call and turns a short count into `io.ErrShortWrite`;
/// this does the same (retrying only after `Interrupted`, which Go's file
/// layer also retries).
pub(crate) fn write_result<W: Write>(
    writer: &mut W,
    result: Option<&PublicResult>,
    text: &[u8],
) -> io::Result<()> {
    let json;
    let data = match result {
        Some(result) => {
            json = result
                .to_json()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            &json[..]
        }
        None => text,
    };
    let n = loop {
        match writer.write(data) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => break other?,
        }
    };
    if n != data.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public values of the golden vector (REFERENCE_FACTS section 2).
    fn golden() -> PublicIdentity {
        PublicIdentity {
            x25519_public: hex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"),
            ed25519_public: hex("29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"),
            identity_hash: hex("aca31af0441d81dbec71e82da0b4b5f5"),
            address: hex("fae321c442e3c9bdcd7a3e79d850e03c"),
        }
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn fixed(mut r: PublicResult) -> String {
        r.version = "5bbe76e".to_owned();
        String::from_utf8(r.to_json().unwrap()).unwrap()
    }

    // How: the reference binary (main-5bbe76e, darwin-arm64) run on a 64-byte
    // file holding the golden fixture's x25519_private || ed25519_seed:
    // `lxmf-vanity --json --inspect golden-public-fixture`.
    #[test]
    fn inspected_json_equals_go() {
        let mut r = PublicResult::new(b"segmented");
        r.status = "inspected";
        r.identity(&golden());
        assert_eq!(
            fixed(r),
            "{\"status\":\"inspected\",\"address\":\"fae321c442e3c9bdcd7a3e79d850e03c\",\"identity_hash\":\"aca31af0441d81dbec71e82da0b4b5f5\",\"x25519_public\":\"8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f\",\"ed25519_public\":\"29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\",\"public_key\":\"8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":0,\"elapsed_seconds\":0,\"generator\":\"segmented\",\"version\":\"5bbe76e\"}\n"
        );
    }

    // How: reference binary, `lxmf-vanity --json --version` and
    // `lxmf-vanity --json --generator independent --version`.
    #[test]
    fn version_json_equals_go() {
        for generator in ["segmented", "independent"] {
            let mut r = PublicResult::new(generator.as_bytes());
            r.status = "version";
            assert_eq!(
                fixed(r),
                format!(
                    "{{\"status\":\"version\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":0,\"elapsed_seconds\":0,\"generator\":\"{generator}\",\"version\":\"5bbe76e\"}}\n"
                )
            );
        }
    }

    // How: reference binary, `lxmf-vanity --json --inspect nonexistent-file`.
    #[test]
    fn failed_json_with_error_equals_go() {
        let mut r = PublicResult::new(b"segmented");
        r.error = b"statat nonexistent-file: no such file or directory".to_vec();
        assert_eq!(
            fixed(r),
            "{\"status\":\"failed\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":0,\"elapsed_seconds\":0,\"generator\":\"segmented\",\"version\":\"5bbe76e\",\"error\":\"statat nonexistent-file: no such file or directory\"}\n"
        );
    }

    // How: reference binary, `lxmf-vanity --json --prefix a --out <tmp>/saved1`
    // in a temporary directory (a throwaway identity; only its public values and
    // the observed attempts and elapsed time are kept). Go printed:
    // {"status":"saved","address":"a22c5ba7510055133a6a5984b714ff4b",…,
    //  "verified_files":["<tmp>/saved1"],…,"attempts":8,"elapsed_seconds":0.000272167,…}
    #[test]
    fn saved_json_with_paths_equals_go() {
        let id = PublicIdentity {
            x25519_public: hex("83ba7d3ea755f5ab3417e4655b1891bc003006d977040f292a3b76e258fb5f2f"),
            ed25519_public: hex("b05b48b0b077b72fd358ef8d30805a1ffb369ca6a7c7f5569209bb5fef2ca479"),
            identity_hash: hex("2aad19d6700285b42512eca6be565d24"),
            address: hex("a22c5ba7510055133a6a5984b714ff4b"),
        };
        let mut r = PublicResult::new(b"segmented");
        r.status = "saved";
        r.identity(&id);
        r.verified_files
            .push(PathBytes::new(b"/tmp/p108/work/saved1".to_vec(), false));
        r.attempts = 8;
        r.elapsed_seconds = 0.000272167;
        assert_eq!(
            fixed(r),
            "{\"status\":\"saved\",\"address\":\"a22c5ba7510055133a6a5984b714ff4b\",\"identity_hash\":\"2aad19d6700285b42512eca6be565d24\",\"x25519_public\":\"83ba7d3ea755f5ab3417e4655b1891bc003006d977040f292a3b76e258fb5f2f\",\"ed25519_public\":\"b05b48b0b077b72fd358ef8d30805a1ffb369ca6a7c7f5569209bb5fef2ca479\",\"public_key\":\"83ba7d3ea755f5ab3417e4655b1891bc003006d977040f292a3b76e258fb5f2fb05b48b0b077b72fd358ef8d30805a1ffb369ca6a7c7f5569209bb5fef2ca479\",\"verified_files\":[\"/tmp/p108/work/saved1\"],\"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":8,\"elapsed_seconds\":0.000272167,\"generator\":\"segmented\",\"version\":\"5bbe76e\"}\n"
        );
    }

    // How: reference binary, `lxmf-vanity --json --benchmark 100ms` and
    // `--json --prefix ab --max-attempts 5 --dry-run` (status limited).
    #[test]
    fn benchmark_and_limited_json_equal_go() {
        let mut r = PublicResult::new(b"segmented");
        r.status = "benchmark";
        r.attempts = 23819;
        r.elapsed_seconds = 0.108908875;
        assert_eq!(
            fixed(r),
            "{\"status\":\"benchmark\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":23819,\"elapsed_seconds\":0.108908875,\"generator\":\"segmented\",\"version\":\"5bbe76e\"}\n"
        );
        let mut r = PublicResult::new(b"segmented");
        r.status = "limited";
        r.attempts = 5;
        r.elapsed_seconds = 0.000183459;
        r.error = b"search attempt limit reached".to_vec();
        assert_eq!(
            fixed(r),
            "{\"status\":\"limited\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":5,\"elapsed_seconds\":0.000183459,\"generator\":\"segmented\",\"version\":\"5bbe76e\",\"error\":\"search attempt limit reached\"}\n"
        );
    }

    #[test]
    fn lists_and_special_strings_are_joined_and_escaped() {
        let mut r = PublicResult::new(b"");
        r.deviations = vec![b"a\"b".to_vec(), b"c".to_vec()];
        r.notices = vec![b"\xff<".to_vec()];
        r.unverified_files = vec![PathBytes::new(b"x\ty".to_vec(), false)];
        assert_eq!(
            fixed(r),
            "{\"status\":\"failed\",\"verified_files\":[],\"unverified_files\":[\"x\\ty\"],\"deviations\":[\"a\\\"b\",\"c\"],\"notices\":[\"\u{FFFD}\\u003c\"],\"attempts\":0,\"elapsed_seconds\":0,\"generator\":\"\",\"version\":\"5bbe76e\"}\n"
        );
    }

    #[test]
    fn new_result_defaults_to_failed_with_the_build_version() {
        let r = PublicResult::new(b"independent");
        assert_eq!(
            (r.status, &r.generator[..]),
            ("failed", &b"independent"[..])
        );
        assert_eq!(r.version, version_string());
        assert!(r.public.is_none() && r.error.is_empty());
    }

    // Derived from Go's `syscall.UTF16ToString`, which uses `utf16.Decode`: each
    // unpaired surrogate becomes one U+FFFD. Not observed on Windows.
    #[test]
    fn windows_path_surrogates_become_one_replacement_each() {
        let wtf8 = b"a\xed\xa0\x80b\xed\xbf\xbfc\xed\x9f\xbf".to_vec();
        let win = PathBytes::new(wtf8.clone(), true);
        assert_eq!(
            &win.go_bytes()[..],
            "a\u{FFFD}b\u{FFFD}c\u{D7FF}".as_bytes()
        );
        // On Unix the same bytes are three invalid bytes each, in the writer.
        let unix = PathBytes::new(wtf8, false);
        let mut r = PublicResult::new(b"segmented");
        r.verified_files = vec![unix];
        let json = String::from_utf8(r.to_json().unwrap()).unwrap();
        assert!(json.contains("[\"a\u{FFFD}\u{FFFD}\u{FFFD}b"), "{json}");
    }

    #[test]
    fn unix_paths_keep_raw_bytes_in_text_and_replace_invalid_ones_in_json() {
        let p = PathBytes::new(b"\xff\x61".to_vec(), false);
        assert_eq!(&p.go_bytes()[..], b"\xff\x61");
    }

    #[test]
    fn non_finite_elapsed_is_an_error() {
        let mut r = PublicResult::new(b"segmented");
        r.elapsed_seconds = f64::NAN;
        let mut out = Vec::new();
        let err = write_result(&mut out, Some(&r), b"").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(out.is_empty());
    }

    struct Short;
    impl Write for Short {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len().saturating_sub(1))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_short_write_is_an_error() {
        let err = write_result(&mut Short, None, b"text\n").unwrap_err();
        assert_eq!(err.to_string(), "short write");
    }

    #[test]
    fn text_is_written_as_given_and_json_ends_with_a_newline() {
        let mut out = Vec::new();
        write_result(&mut out, None, b"Search failed: x\n").unwrap();
        assert_eq!(out, b"Search failed: x\n");
        let mut out = Vec::new();
        write_result(&mut out, Some(&PublicResult::new(b"segmented")), b"ignored").unwrap();
        assert!(out.starts_with(b"{\"status\":\"failed\"") && out.ends_with(b"}\n"));
    }

    #[test]
    fn interrupted_writes_are_retried() {
        struct Flaky(bool, Vec<u8>);
        impl Write for Flaky {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.1.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = Flaky(false, Vec::new());
        write_result(&mut w, None, b"ok\n").unwrap();
        assert_eq!(w.1, b"ok\n");
    }
}
