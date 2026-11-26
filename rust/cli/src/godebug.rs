//! The FIPS 140 setting in `GODEBUG` (owner decision R-4).
//!
//! Go reads `GODEBUG=fips140=...` before `main` runs. This build has no
//! FIPS 140-3 validated module, so it honors an explicit request by refusing
//! it, with Go's parsing and precedence rules.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "called by the console entry point (P1-09)")
)]

use std::ffi::OsStr;
use std::fmt;

/// Exit status when the setting is unknown (a parse failure in Go).
pub(crate) const EXIT_UNKNOWN: u8 = 2;
/// Exit status when the setting is refused at run time (a failed self-test).
pub(crate) const EXIT_REFUSED: u8 = 1;

/// Value of the rightmost `fips140` key in `GODEBUG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FipsSetting {
    Absent,
    /// `fips140=off` and `fips140=`.
    Off,
    On,
    Debug,
    Only,
    /// Any other value, as raw bytes (also every non-UTF-8 value).
    Unknown(Vec<u8>),
}

/// Reads `GODEBUG` with `var_os`, so a non-UTF-8 value cannot be lost.
pub(crate) fn fips_setting_from_env() -> FipsSetting {
    fips_setting(std::env::var_os("GODEBUG").as_deref())
}

/// Port of `internal/godebug` `parse`, reduced to the key `fips140`.
///
/// Segments are scanned from the right and the first one whose key is exactly
/// `fips140` wins. The key is the text before the first `=`; segments without
/// `=` are ignored; the value ends at the first `#`; nothing is trimmed.
pub(crate) fn fips_setting(env: Option<&OsStr>) -> FipsSetting {
    let Some(env) = env else {
        return FipsSetting::Absent;
    };
    for segment in env.as_encoded_bytes().rsplit(|&b| b == b',') {
        let Some(eq) = segment.iter().position(|&b| b == b'=') else {
            continue;
        };
        if &segment[..eq] != b"fips140" {
            continue;
        }
        let arg = &segment[eq + 1..];
        let value = arg.split(|&b| b == b'#').next().unwrap_or(arg);
        // Port of crypto/internal/fips140 init.
        return match value {
            b"off" | b"" => FipsSetting::Off,
            b"on" => FipsSetting::On,
            b"debug" => FipsSetting::Debug,
            b"only" => FipsSetting::Only,
            other => FipsSetting::Unknown(other.to_vec()),
        };
    }
    FipsSetting::Absent
}

/// Policy point 1: before argument parsing, for every command.
/// Go fails here too (a panic before `main`), so `--version` and `--help` fail.
pub(crate) fn check_known(setting: &FipsSetting) -> Result<(), UnknownFips<'_>> {
    match setting {
        FipsSetting::Unknown(value) => Err(UnknownFips(value)),
        _ => Ok(()),
    }
}

/// An unrecognized `fips140` value. Exit status [`EXIT_UNKNOWN`]; the message
/// goes to stderr, stdout stays empty.
#[derive(Debug)]
pub(crate) struct UnknownFips<'a>(&'a [u8]);

impl UnknownFips<'_> {
    /// The message without the `Error: ` prefix. `quote` is Go's `%q`
    /// (`goquote`), which this module does not own.
    pub(crate) fn message(&self, quote: impl Fn(&[u8]) -> String) -> String {
        format!(
            "unrecognized GODEBUG setting fips140={}; this build accepts off, on, debug or only",
            quote(self.0)
        )
    }
}

/// Policy point 2: after help, version and validation, before the self-test
/// or any file access. The error is the text of the normal `failed` result
/// (`attempts` 0); exit status [`EXIT_REFUSED`].
pub(crate) fn check_runtime(setting: &FipsSetting) -> Result<(), FipsRefused> {
    match setting {
        FipsSetting::Only => Err(FipsRefused::Only),
        FipsSetting::On => Err(FipsRefused::On),
        FipsSetting::Debug => Err(FipsRefused::Debug),
        FipsSetting::Absent | FipsSetting::Off | FipsSetting::Unknown(_) => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FipsRefused {
    Only,
    On,
    Debug,
}

impl fmt::Display for FipsRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The prefix up to "unavailable" is a contract (`make gate`, conformance cases).
            Self::Only => f.write_str(
                "self-test failed: X25519 public-key derivation unavailable: FIPS 140-only mode was requested (GODEBUG=fips140=only); this build has no FIPS 140-3 validated cryptographic module",
            ),
            Self::On => f.write_str(
                "FIPS 140-3 mode was requested (GODEBUG=fips140=on); this build has no FIPS 140-3 validated cryptographic module",
            ),
            Self::Debug => f.write_str(
                "FIPS 140-3 mode was requested (GODEBUG=fips140=debug); this build has no FIPS 140-3 validated cryptographic module",
            ),
        }
    }
}

impl std::error::Error for FipsRefused {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> FipsSetting {
        fips_setting(Some(OsStr::new(s)))
    }

    fn unknown(s: &str) -> FipsSetting {
        FipsSetting::Unknown(s.as_bytes().to_vec())
    }

    // REFERENCE_FACTS §6 table, row by row.
    #[test]
    fn parses_every_row_of_the_reference_table() {
        assert_eq!(fips_setting(None), FipsSetting::Absent);
        assert_eq!(parse("fips140=off"), FipsSetting::Off);
        assert_eq!(parse("fips140="), FipsSetting::Off);
        assert_eq!(parse("fips140=on"), FipsSetting::On);
        assert_eq!(parse("fips140=debug"), FipsSetting::Debug);
        assert_eq!(parse("fips140=only"), FipsSetting::Only);
        assert_eq!(parse("fips140=on,fips140=only"), FipsSetting::Only);
        assert_eq!(parse("x=1,fips140=only"), FipsSetting::Only);
        assert_eq!(parse("fips140=only,x=1"), FipsSetting::Only);
        assert_eq!(parse("fips140=only,fips140=off"), FipsSetting::Off);
        assert_eq!(parse("fips140=bogus"), unknown("bogus"));
    }

    #[test]
    fn rightmost_fips140_wins_even_over_unknown_values() {
        assert_eq!(parse("fips140=bogus,fips140=off"), FipsSetting::Off);
        assert_eq!(parse("fips140=off,fips140=bogus"), unknown("bogus"));
    }

    #[test]
    fn environment_wrapper_reads_godebug_without_utf8_loss() {
        let raw = std::env::var_os("GODEBUG");
        assert_eq!(fips_setting_from_env(), fips_setting(raw.as_deref()));
    }

    #[test]
    fn empty_godebug_is_absent() {
        assert_eq!(parse(""), FipsSetting::Absent);
        assert_eq!(parse(","), FipsSetting::Absent);
    }

    #[test]
    fn segment_without_equals_is_ignored() {
        assert_eq!(parse("fips140"), FipsSetting::Absent);
        // The valueless segment on the right does not hide the one on the left.
        assert_eq!(parse("fips140=only,fips140"), FipsSetting::Only);
    }

    #[test]
    fn empty_key_is_ignored() {
        assert_eq!(parse("=only"), FipsSetting::Absent);
    }

    #[test]
    fn value_is_cut_at_the_first_hash() {
        assert_eq!(parse("fips140=only#tag"), FipsSetting::Only);
        assert_eq!(parse("fips140=#only"), FipsSetting::Off);
        assert_eq!(parse("fips140=on#a#b"), FipsSetting::On);
    }

    #[test]
    fn values_and_keys_are_case_sensitive_and_never_trimmed() {
        assert_eq!(parse("fips140=ONLY"), unknown("ONLY"));
        assert_eq!(parse("fips140= only"), unknown(" only"));
        assert_eq!(parse("fips140=only "), unknown("only "));
        assert_eq!(parse("FIPS140=only"), FipsSetting::Absent);
        // A different key, not `fips140`.
        assert_eq!(parse("fips140 =only"), FipsSetting::Absent);
        assert_eq!(parse(" fips140=only"), FipsSetting::Absent);
    }

    #[test]
    fn value_is_everything_after_the_first_equals() {
        assert_eq!(parse("fips140=a=b"), unknown("a=b"));
        assert_eq!(parse("fips140==only"), unknown("=only"));
    }

    #[test]
    fn other_godebug_keys_are_ignored() {
        assert_eq!(parse("http2debug=1"), FipsSetting::Absent);
        assert_eq!(parse("http2debug=1,fips140=only,x"), FipsSetting::Only);
        assert_eq!(parse("fips1400=only"), FipsSetting::Absent);
    }

    #[test]
    fn very_long_inputs_are_handled() {
        let long = "x".repeat(1 << 20);
        assert_eq!(parse(&long), FipsSetting::Absent);
        assert_eq!(parse(&format!("{long}=1,fips140=only")), FipsSetting::Only);
        assert_eq!(parse(&format!("fips140={long}")), unknown(&long));
        let many = "a=b,".repeat(100_000);
        assert_eq!(parse(&format!("fips140=on,{many}")), FipsSetting::On);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_value_is_unknown_and_keeps_its_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let raw = b"fips140=on\xff";
        assert_eq!(
            fips_setting(Some(OsStr::from_bytes(raw))),
            FipsSetting::Unknown(b"on\xff".to_vec())
        );
        // Invalid bytes in another key do not disturb the lookup.
        let raw = b"\xff=1,fips140=only";
        assert_eq!(
            fips_setting(Some(OsStr::from_bytes(raw))),
            FipsSetting::Only
        );
    }

    #[test]
    fn unknown_setting_fails_before_parsing_with_exit_2() {
        let setting = parse("fips140=bogus");
        let err = check_known(&setting).unwrap_err();
        let quote = |b: &[u8]| format!("\"{}\"", String::from_utf8_lossy(b));
        assert_eq!(
            err.message(quote),
            "unrecognized GODEBUG setting fips140=\"bogus\"; this build accepts off, on, debug or only"
        );
        assert_eq!(EXIT_UNKNOWN, 2);
    }

    #[test]
    fn known_settings_pass_the_before_parsing_point() {
        for s in [
            FipsSetting::Absent,
            FipsSetting::Off,
            FipsSetting::On,
            FipsSetting::Debug,
            FipsSetting::Only,
        ] {
            assert!(check_known(&s).is_ok());
        }
    }

    #[test]
    fn unknown_setting_does_not_stop_the_runtime_point() {
        // Reached only after `check_known` has already failed; never refuses twice.
        assert!(check_runtime(&unknown("bogus")).is_ok());
    }

    #[test]
    fn absent_and_off_continue_at_the_runtime_point() {
        assert!(check_runtime(&FipsSetting::Absent).is_ok());
        assert!(check_runtime(&FipsSetting::Off).is_ok());
    }

    #[test]
    fn only_is_refused_with_the_self_test_message() {
        let err = check_runtime(&FipsSetting::Only).unwrap_err();
        assert_eq!(
            err.to_string(),
            "self-test failed: X25519 public-key derivation unavailable: FIPS 140-only mode was requested (GODEBUG=fips140=only); this build has no FIPS 140-3 validated cryptographic module"
        );
        // Contract used by `make gate`.
        assert!(
            err.to_string()
                .contains("X25519 public-key derivation unavailable")
        );
        assert_eq!(EXIT_REFUSED, 1);
    }

    #[test]
    fn on_and_debug_are_refused_naming_the_requested_value() {
        assert_eq!(
            check_runtime(&FipsSetting::On).unwrap_err().to_string(),
            "FIPS 140-3 mode was requested (GODEBUG=fips140=on); this build has no FIPS 140-3 validated cryptographic module"
        );
        assert_eq!(
            check_runtime(&FipsSetting::Debug).unwrap_err().to_string(),
            "FIPS 140-3 mode was requested (GODEBUG=fips140=debug); this build has no FIPS 140-3 validated cryptographic module"
        );
    }
}
