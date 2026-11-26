//! Command-line grammar, validation and error rendering, identical to the Go tool.
//!
//! Three separate stages: [`parse`] mirrors `flag.FlagSet.Parse` (ContinueOnError) and only
//! records values; [`validate`] mirrors `validateInputs` in Go's `config.go`, in Go's order;
//! [`render_error`] prints what Go's `main` prints. No CLI framework is used on purpose: the
//! grammar of Go's `flag` package is narrow and must not drift.
//!
//! Basis: the worker default and the duration test cases come from the example rewrite
//! (basis snapshot 2026-11-25); the parser itself is new.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};

use crate::goparse::{self, NumError};
use crate::goquote::{quote_into, quote_list_into};

/// Largest accepted `--workers` value (`maxWorkerCount` in Go).
pub(crate) const MAX_WORKERS: usize = 256;
/// Hex characters in an LXMF address (`addressHexLength` in Go).
const ADDRESS_HEX_LENGTH: usize = 32;
/// Exit status of every parse or validation error.
pub(crate) const EXIT_USAGE: u8 = 2;

/// Port of `defaultWorkerCount`: the usable parallelism clamped to `1..=256`, 1 if unknown.
/// See `DEV-workers-default`: Go's `GOMAXPROCS` also honors the environment variable.
pub(crate) fn default_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().clamp(1, MAX_WORKERS))
}

// ---------------------------------------------------------------------------------------
// Flag table (Go: the `flags.XxxVar` calls in `parseArgs`)
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    Int,
    Uint,
    Duration,
    Str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Id {
    AllowInheritedWindowsAcl,
    AllowWeakOutputProtection,
    Benchmark,
    DryRun,
    FallbackOut,
    Generator,
    IncludePrivateExports,
    Inspect,
    Json,
    MaxAttempts,
    Out,
    Postfix,
    Prefix,
    SaveRetryTimeout,
    Timeout,
    Version,
    Workers,
}

#[derive(Clone, Copy)]
enum Default {
    /// Zero value of the type: not printed in the usage text.
    Zero,
    Text(&'static str),
    Workers,
}

struct FlagDef {
    name: &'static str,
    id: Id,
    kind: Kind,
    usage: &'static str,
    default: Default,
}

const fn def(
    name: &'static str,
    id: Id,
    kind: Kind,
    default: Default,
    usage: &'static str,
) -> FlagDef {
    FlagDef {
        name,
        id,
        kind,
        usage,
        default,
    }
}

/// Sorted by name, as `FlagSet.VisitAll` prints them. Usage strings are Go's, verbatim.
static FLAGS: [FlagDef; 17] = [
    def(
        "allow-inherited-windows-acl",
        Id::AllowInheritedWindowsAcl,
        Kind::Bool,
        Default::Zero,
        "On Windows, explicitly accept the output directory's inherited ACL for private files",
    ),
    def(
        "allow-weak-output-protection",
        Id::AllowWeakOutputProtection,
        Kind::Bool,
        Default::Zero,
        "Explicitly accept failed/unavailable output protection checks",
    ),
    def(
        "benchmark",
        Id::Benchmark,
        Kind::Duration,
        Default::Zero,
        "Benchmark full identity generation for a duration (for example 30s); no identity is selected or saved",
    ),
    def(
        "dry-run",
        Id::DryRun,
        Kind::Bool,
        Default::Zero,
        "Find a match but do not save it",
    ),
    def(
        "fallback-out",
        Id::FallbackOut,
        Kind::Str,
        Default::Zero,
        "Preflighted secondary identity file for save recovery",
    ),
    def(
        "generator",
        Id::Generator,
        Kind::Str,
        Default::Text("segmented"),
        "Candidate generator: segmented or independent",
    ),
    def(
        "include-private-exports",
        Id::IncludePrivateExports,
        Kind::Bool,
        Default::Zero,
        "Include reversible private-key exports in <out>.txt (sensitive)",
    ),
    def(
        "inspect",
        Id::Inspect,
        Kind::Str,
        Default::Zero,
        "Print public metadata for a 64-byte identity; write nothing",
    ),
    def(
        "json",
        Id::Json,
        Kind::Bool,
        Default::Zero,
        "Write one public JSON result to stdout",
    ),
    def(
        "max-attempts",
        Id::MaxAttempts,
        Kind::Uint,
        Default::Zero,
        "Maximum reserved candidates; 0 is unlimited",
    ),
    def(
        "out",
        Id::Out,
        Kind::Str,
        Default::Text("identity"),
        "Output path for identity file",
    ),
    def(
        "postfix",
        Id::Postfix,
        Kind::Str,
        Default::Zero,
        "Desired hex postfix/suffix (1-32 chars)",
    ),
    def(
        "prefix",
        Id::Prefix,
        Kind::Str,
        Default::Zero,
        "Desired hex prefix (1-32 chars)",
    ),
    def(
        "save-retry-timeout",
        Id::SaveRetryTimeout,
        Kind::Duration,
        Default::Zero,
        "Save recovery deadline; 0 retries indefinitely (cannot interrupt blocked I/O)",
    ),
    def(
        "timeout",
        Id::Timeout,
        Kind::Duration,
        Default::Zero,
        "Search timeout; 0 is unlimited (does not limit saving)",
    ),
    def(
        "version",
        Id::Version,
        Kind::Bool,
        Default::Zero,
        "Print version, Go version and target without searching",
    ),
    def(
        "workers",
        Id::Workers,
        Kind::Int,
        Default::Workers,
        "Number of parallel workers",
    ),
];

/// Port of `flag.PrintDefaults` for this flag set, preceded by `Usage of lxmf-vanity:`.
pub(crate) fn usage_text(default_workers: usize) -> String {
    let mut text = String::from("Usage of lxmf-vanity:\n");
    for flag in &FLAGS {
        text.push_str("  -");
        text.push_str(flag.name);
        match flag.kind {
            Kind::Bool => {}
            Kind::Int => text.push_str(" int"),
            Kind::Uint => text.push_str(" uint"),
            Kind::Duration => text.push_str(" duration"),
            Kind::Str => text.push_str(" string"),
        }
        // The name is longer than one letter, so the usage goes on its own line.
        text.push_str("\n    \t");
        text.push_str(flag.usage);
        match flag.default {
            Default::Zero => {}
            Default::Text(d) => {
                text.push_str(" (default \"");
                text.push_str(d);
                text.push_str("\")");
            }
            Default::Workers => {
                text.push_str(" (default ");
                text.push_str(&default_workers.to_string());
                text.push(')');
            }
        }
        text.push('\n');
    }
    text
}

fn lookup(name: &[u8]) -> Option<&'static FlagDef> {
    FLAGS.iter().find(|f| f.name.as_bytes() == name)
}

// ---------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------

/// Every flag value in Go's types, before validation (Go: `config` right after `Parse`).
pub(crate) struct RawConfig {
    pub prefix: Vec<u8>,
    pub postfix: Vec<u8>,
    pub workers: i64,
    pub out: OsString,
    pub fallback_out: OsString,
    pub inspect: OsString,
    pub generator: Vec<u8>,
    pub save_retry_timeout_ns: i64,
    pub timeout_ns: i64,
    pub benchmark_ns: i64,
    pub max_attempts: u64,
    pub dry_run: bool,
    pub include_private_exports: bool,
    pub allow_inherited_windows_acl: bool,
    pub allow_weak_output_protection: bool,
    pub json: bool,
    pub version: bool,
    /// Flags given on the command line, each once, in order of first appearance.
    pub explicit: Vec<&'static str>,
}

impl RawConfig {
    fn new(default_workers: usize) -> Self {
        RawConfig {
            prefix: Vec::new(),
            postfix: Vec::new(),
            workers: i64::try_from(default_workers).unwrap_or(1),
            out: OsString::from("identity"),
            fallback_out: OsString::new(),
            inspect: OsString::new(),
            generator: b"segmented".to_vec(),
            save_retry_timeout_ns: 0,
            timeout_ns: 0,
            benchmark_ns: 0,
            max_attempts: 0,
            dry_run: false,
            include_private_exports: false,
            allow_inherited_windows_acl: false,
            allow_weak_output_protection: false,
            json: false,
            version: false,
            explicit: Vec::new(),
        }
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "built once per run; boxing would only add noise"
)]
pub(crate) enum Parsed {
    /// `-h`, `-help` or `--help`: print the usage on stderr and exit 0.
    Help,
    Raw(RawConfig),
}

/// A command-line error. The message is bytes because it can echo arguments verbatim.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// Reported by the `flag` package: the message is followed by the usage text.
    Flag(Vec<u8>),
    /// Leftover arguments, reported by `parseArgs` after `Parse`: no usage text.
    Positional(Vec<u8>),
}

impl ParseError {
    pub(crate) fn message(&self) -> &[u8] {
        match self {
            ParseError::Flag(m) | ParseError::Positional(m) => m,
        }
    }
}

/// The bytes Go would see for one argument. On Windows Go decodes UTF-16 and replaces every
/// unpaired surrogate with U+FFFD, which is what `to_string_lossy` does there.
fn arg_bytes(arg: &OsStr) -> Cow<'_, [u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Cow::Borrowed(arg.as_bytes())
    }
    #[cfg(not(unix))]
    {
        match arg.to_string_lossy() {
            Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
            Cow::Owned(s) => Cow::Owned(s.into_bytes()),
        }
    }
}

/// The part of `arg` after byte offset `start` (just past an ASCII `=`), as an `OsString`.
fn os_tail(arg_bytes: &[u8], start: usize) -> OsString {
    let tail = arg_bytes.get(start..).unwrap_or_default();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(tail).to_os_string()
    }
    #[cfg(not(unix))]
    {
        // The bytes came from a lossy UTF-8 conversion and were split at an ASCII byte.
        OsString::from(String::from_utf8_lossy(tail).into_owned())
    }
}

fn message(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn flag_error(parts: &[&[u8]]) -> ParseError {
    ParseError::Flag(message(parts))
}

/// Why a value was rejected, as `flag` prints it after `numError`.
fn reason(e: NumError) -> &'static str {
    match e {
        NumError::Syntax => "parse error",
        NumError::Range => "value out of range",
    }
}

/// Stores one non-boolean value. `value_os` is only called for path flags.
fn set_value(
    raw: &mut RawConfig,
    flag: &FlagDef,
    value: &[u8],
    value_os: impl FnOnce() -> OsString,
) -> Result<(), &'static str> {
    // `time.ParseDuration` errors all become "parse error" in `durationValue.Set`.
    let duration = |v: &[u8]| goparse::parse_duration(v).map_err(|_| "parse error");
    match flag.id {
        Id::Workers => raw.workers = goparse::parse_int(value).map_err(reason)?,
        Id::MaxAttempts => raw.max_attempts = goparse::parse_uint(value).map_err(reason)?,
        Id::Benchmark => raw.benchmark_ns = duration(value)?,
        Id::Timeout => raw.timeout_ns = duration(value)?,
        Id::SaveRetryTimeout => raw.save_retry_timeout_ns = duration(value)?,
        Id::Prefix => raw.prefix = value.to_vec(),
        Id::Postfix => raw.postfix = value.to_vec(),
        Id::Generator => raw.generator = value.to_vec(),
        Id::Out => raw.out = value_os(),
        Id::FallbackOut => raw.fallback_out = value_os(),
        Id::Inspect => raw.inspect = value_os(),
        // Boolean flags never reach here.
        Id::AllowInheritedWindowsAcl
        | Id::AllowWeakOutputProtection
        | Id::DryRun
        | Id::IncludePrivateExports
        | Id::Json
        | Id::Version => {}
    }
    Ok(())
}

fn set_bool(raw: &mut RawConfig, id: Id, v: bool) {
    match id {
        Id::AllowInheritedWindowsAcl => raw.allow_inherited_windows_acl = v,
        Id::AllowWeakOutputProtection => raw.allow_weak_output_protection = v,
        Id::DryRun => raw.dry_run = v,
        Id::IncludePrivateExports => raw.include_private_exports = v,
        Id::Json => raw.json = v,
        Id::Version => raw.version = v,
        _ => {}
    }
}

/// Port of `flag.FlagSet.Parse` with `ContinueOnError`, then of the positional check in
/// `parseArgs`. `args` excludes the program name. `default_workers` is the `-workers` default.
pub(crate) fn parse(args: &[OsString], default_workers: usize) -> Result<Parsed, ParseError> {
    let mut raw = RawConfig::new(default_workers);
    let mut i = 0;
    // Go: `for { seen, err := f.parseOne(); ... }`
    while let Some(arg) = args.get(i) {
        let s = arg_bytes(arg);
        if s.len() < 2 || s[0] != b'-' {
            break;
        }
        let mut dashes = 1;
        if s[1] == b'-' {
            dashes = 2;
            if s.len() == 2 {
                i += 1; // "--" ends the flags and is consumed
                break;
            }
        }
        let spec = &s[dashes..];
        if spec.is_empty() || spec[0] == b'-' || spec[0] == b'=' {
            return Err(flag_error(&[b"bad flag syntax: ", &s]));
        }
        i += 1;
        // The first '=' after the first character separates the value.
        let eq = spec.iter().skip(1).position(|&b| b == b'=').map(|p| p + 1);
        let (name, value) = match eq {
            Some(p) => (&spec[..p], Some(&spec[p + 1..])),
            None => (spec, None),
        };
        let Some(flag) = lookup(name) else {
            if name == b"help" || name == b"h" {
                return Ok(Parsed::Help);
            }
            return Err(flag_error(&[b"flag provided but not defined: -", name]));
        };
        if flag.kind == Kind::Bool {
            let parsed = match value {
                None => true,
                Some(v) => goparse::parse_bool(v).map_err(|_| {
                    let mut m = b"invalid boolean value ".to_vec();
                    quote_into(&mut m, v);
                    m.extend_from_slice(b" for -");
                    m.extend_from_slice(name);
                    m.extend_from_slice(b": parse error");
                    ParseError::Flag(m)
                })?,
            };
            set_bool(&mut raw, flag.id, parsed);
        } else {
            // A value that is not attached with '=' is the next argument, whatever it is.
            let (bytes, os): (Cow<'_, [u8]>, OsString) = match (value, args.get(i)) {
                (Some(v), _) => {
                    // `eq` is Some here: the value starts after the '=' at that offset.
                    let start = dashes + eq.unwrap_or(0) + 1;
                    (Cow::Borrowed(v), os_tail(&s, start))
                }
                (None, Some(next)) => {
                    i += 1;
                    (arg_bytes(next), next.clone())
                }
                (None, None) => {
                    return Err(flag_error(&[b"flag needs an argument: -", name]));
                }
            };
            set_value(&mut raw, flag, &bytes, || os).map_err(|why| {
                let mut m = b"invalid value ".to_vec();
                quote_into(&mut m, &bytes);
                m.extend_from_slice(b" for flag -");
                m.extend_from_slice(name);
                m.extend_from_slice(b": ");
                m.extend_from_slice(why.as_bytes());
                ParseError::Flag(m)
            })?;
        }
        if !raw.explicit.contains(&flag.name) {
            raw.explicit.push(flag.name);
        }
    }
    if i < args.len() {
        let mut m = b"unexpected positional arguments ".to_vec();
        quote_list_into(&mut m, args[i..].iter().map(|a| arg_bytes(a)));
        m.extend_from_slice(b"; all options must use flags");
        return Err(ParseError::Positional(m));
    }
    Ok(Parsed::Raw(raw))
}

// Texts below were compared with the reference binary (main at 5bbe76e); see the validation
// stage for the byte-for-byte comparison of full error output.
#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn raw(args: &[&str]) -> RawConfig {
        match parse(&os(args), 8) {
            Ok(Parsed::Raw(raw)) => raw,
            _ => panic!("expected a raw config for {args:?}"),
        }
    }

    const USAGE_8: &str = "Usage of lxmf-vanity:
  -allow-inherited-windows-acl
    \tOn Windows, explicitly accept the output directory's inherited ACL for private files
  -allow-weak-output-protection
    \tExplicitly accept failed/unavailable output protection checks
  -benchmark duration
    \tBenchmark full identity generation for a duration (for example 30s); no identity is selected or saved
  -dry-run
    \tFind a match but do not save it
  -fallback-out string
    \tPreflighted secondary identity file for save recovery
  -generator string
    \tCandidate generator: segmented or independent (default \"segmented\")
  -include-private-exports
    \tInclude reversible private-key exports in <out>.txt (sensitive)
  -inspect string
    \tPrint public metadata for a 64-byte identity; write nothing
  -json
    \tWrite one public JSON result to stdout
  -max-attempts uint
    \tMaximum reserved candidates; 0 is unlimited
  -out string
    \tOutput path for identity file (default \"identity\")
  -postfix string
    \tDesired hex postfix/suffix (1-32 chars)
  -prefix string
    \tDesired hex prefix (1-32 chars)
  -save-retry-timeout duration
    \tSave recovery deadline; 0 retries indefinitely (cannot interrupt blocked I/O)
  -timeout duration
    \tSearch timeout; 0 is unlimited (does not limit saving)
  -version
    \tPrint version, Go version and target without searching
  -workers int
    \tNumber of parallel workers (default 8)
";

    #[test]
    fn usage_text_is_byte_identical_to_go() {
        // Go: REFERENCE_FACTS §3, observed from `lxmf-vanity --help` with 8 workers.
        assert_eq!(usage_text(8), USAGE_8);
        assert_eq!(usage_text(3), USAGE_8.replace("(default 8)", "(default 3)"));
    }

    #[test]
    fn flag_table_is_sorted_and_names_are_unique() {
        assert!(FLAGS.windows(2).all(|w| w[0].name < w[1].name));
    }

    #[test]
    fn help_spellings_mean_help_even_after_other_flags() {
        for args in [
            &["-h"][..],
            &["-help"],
            &["--help"],
            &["--h"],
            &["--help=x"],
            &["--prefix", "a", "-h"],
        ] {
            assert!(matches!(parse(&os(args), 8), Ok(Parsed::Help)), "{args:?}");
        }
    }

    #[test]
    fn a_parse_error_comes_before_help_and_help_ends_parsing() {
        assert!(parse(&os(&["--nope", "-h"]), 8).is_err());
        // Parsing stops at help, so nothing after it is looked at.
        assert!(matches!(
            parse(&os(&["-h", "--nope", "x"]), 8),
            Ok(Parsed::Help)
        ));
    }

    #[test]
    fn accepts_the_grammar_rows_of_reference_facts_4() {
        // (arguments, workers, benchmark nanoseconds, json)
        let rows: &[(&[&str], i64, i64, bool)] = &[
            (
                &["--benchmark", "1ms", "--workers", "010", "--json"],
                8,
                1_000_000,
                true,
            ),
            (
                &["-benchmark=1ms", "-workers", "0x2", "-json"],
                2,
                1_000_000,
                true,
            ),
            (
                &["--benchmark", "1.5ms", "--workers=1"],
                1,
                1_500_000,
                false,
            ),
            (&["--benchmark", ".5ms", "--workers=1"], 1, 500_000, false),
            (&["--benchmark", "+1ms", "--workers=1"], 1, 1_000_000, false),
            (&["--benchmark", "1.ms", "--workers=1"], 1, 1_000_000, false),
            (&["--benchmark", "1us", "--workers=1"], 1, 1_000, false),
            (&["--benchmark", "1\u{b5}s", "--workers=1"], 1, 1_000, false),
            (
                &["--benchmark=1ms", "--workers=0b11", "--json=1"],
                3,
                1_000_000,
                true,
            ),
            (
                &["--benchmark=1ms", "--workers=0o7", "--json=T"],
                7,
                1_000_000,
                true,
            ),
            (
                &["--benchmark=1ms", "--workers=1_0", "--json=false"],
                10,
                1_000_000,
                false,
            ),
            (
                &["--benchmark=1ms", "--workers=-0", "--json=0"],
                0,
                1_000_000,
                false,
            ),
            (
                &["--benchmark=1ms", "--workers=+5", "--json=TRUE"],
                5,
                1_000_000,
                true,
            ),
        ];
        for &(args, workers, bench, json) in rows {
            let r = raw(args);
            assert_eq!(
                (r.workers, r.benchmark_ns, r.json),
                (workers, bench, json),
                "{args:?}"
            );
        }
    }

    #[test]
    fn flag_value_is_the_next_argument_whatever_it_looks_like() {
        let r = raw(&[
            "--prefix",
            "--json",
            "--out",
            "-",
            "--postfix",
            "--",
            "--workers",
            "-3",
        ]);
        assert_eq!(r.prefix, b"--json");
        assert_eq!(r.out, OsString::from("-"));
        assert_eq!(r.postfix, b"--");
        assert_eq!(r.workers, -3);
        assert!(!r.json);
        // An explicit empty value is a value.
        let r = raw(&["--prefix=", "--generator", ""]);
        assert_eq!(r.prefix, b"");
        assert_eq!(r.generator, b"");
        assert_eq!(r.explicit, ["prefix", "generator"]);
    }

    #[test]
    fn repeated_flags_keep_the_last_value_and_the_first_position() {
        let r = raw(&["--prefix", "a", "--json", "--prefix=b", "-json=false"]);
        assert_eq!(r.prefix, b"b");
        assert!(!r.json);
        assert_eq!(r.explicit, ["prefix", "json"]);
    }

    #[cfg(unix)]
    #[test]
    fn unix_arguments_are_not_converted_lossily() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let bad = OsString::from_vec(vec![b'o', 0xff, 0xfe]);
        let args = vec![
            OsString::from("--out"),
            bad.clone(),
            OsString::from("--fallback-out=x\u{ff}"),
            OsString::from_vec(b"--inspect=\xc3".to_vec()),
            OsString::from("--prefix"),
            OsString::from_vec(vec![0xff, b'a']),
        ];
        let Ok(Parsed::Raw(r)) = parse(&args, 8) else {
            panic!("expected raw config");
        };
        assert_eq!(r.out, bad);
        assert_eq!(r.fallback_out.as_bytes(), b"x\xc3\xbf");
        assert_eq!(r.inspect.as_bytes(), b"\xc3");
        assert_eq!(r.prefix, [0xff, b'a']);
        // The same bytes in a message are quoted the way Go's %q does.
        let args = vec![OsString::from_vec(b"a\xffb".to_vec())];
        let Err(e) = parse(&args, 8) else {
            panic!("expected positional error")
        };
        assert_eq!(
            e.message(),
            &b"unexpected positional arguments [\"a\\xffb\"]; all options must use flags"[..]
        );
        let args = vec![
            OsString::from("-workers"),
            OsString::from_vec(b"\xff1".to_vec()),
        ];
        let Err(ParseError::Flag(m)) = parse(&args, 8) else {
            panic!("expected flag error")
        };
        assert_eq!(
            m,
            b"invalid value \"\\xff1\" for flag -workers: parse error"
        );
        // An unknown flag name is echoed raw, not quoted.
        let args = vec![OsString::from_vec(b"-n\xffx".to_vec())];
        let Err(ParseError::Flag(m)) = parse(&args, 8) else {
            panic!("expected flag error")
        };
        assert_eq!(m, b"flag provided but not defined: -n\xffx");
    }
}
