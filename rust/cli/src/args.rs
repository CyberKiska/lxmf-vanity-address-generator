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
use std::io::{self, Write};
use std::time::Duration;

use lxmf_vanity_core::matcher::validate_patterns;

use crate::goparse::{self, NumError};
use crate::goquote::{quote_into, quote_list_into};

/// Largest accepted `--workers` value (`maxWorkerCount` in Go).
pub(crate) const MAX_WORKERS: usize = 256;
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

// ---------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TargetOs {
    Windows,
    Other,
}

impl TargetOs {
    pub(crate) fn host() -> Self {
        if cfg!(windows) {
            TargetOs::Windows
        } else {
            TargetOs::Other
        }
    }
}

/// The candidate generator. Go accepts an empty string, prints it, and behaves as segmented.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Generator {
    Empty,
    Segmented,
    Independent,
}

impl Generator {
    /// The text Go prints and puts in the JSON `generator` field.
    pub(crate) fn as_bytes(self) -> &'static [u8] {
        match self {
            Generator::Empty => b"",
            Generator::Segmented => b"segmented",
            Generator::Independent => b"independent",
        }
    }
}

/// Validated settings of a search, benchmark or dry run.
pub(crate) struct RunConfig {
    /// Lowercase ASCII hex, at most 32 bytes, validated.
    pub prefix: Vec<u8>,
    pub postfix: Vec<u8>,
    pub workers: usize,
    pub out: OsString,
    pub fallback_out: Option<OsString>,
    pub generator: Generator,
    /// Zero means unlimited.
    pub timeout: Duration,
    pub save_retry_timeout: Duration,
    pub max_attempts: u64,
    /// `Some` only for a positive `--benchmark`; `--benchmark 0` is no benchmark.
    pub benchmark: Option<Duration>,
    pub dry_run: bool,
    pub include_private_exports: bool,
    pub allow_inherited_windows_acl: bool,
    pub allow_weak_output_protection: bool,
    pub json: bool,
}

/// The mode the command line selects. `--version` and `--inspect` skip the checks that
/// follow them in Go, so they carry only what their output needs.
pub(crate) enum Config {
    Version {
        json: bool,
        /// Unvalidated: Go's JSON result echoes whatever `--generator` held.
        generator: Vec<u8>,
    },
    Inspect {
        path: OsString,
        json: bool,
    },
    Run(RunConfig),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidationError(pub(crate) String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, ValidationError> {
    Err(ValidationError(msg.into()))
}

/// Port of Go's `strings.ToLower` as far as it can change a pattern's validity or length:
/// ASCII letters are lowercased, an invalid byte becomes U+FFFD (3 bytes) and any other rune
/// maps through Unicode's simple lowercase mapping. The result is only ever used for the
/// length check and the hex check, so a non-ASCII rune simply stays non-hex.
pub(crate) fn go_to_lower(s: &[u8]) -> Vec<u8> {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s;
    while let Some(&first) = rest.first() {
        let width = match first {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let decoded = rest
            .get(..width)
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|t| t.chars().next());
        let mut buf = [0u8; 4];
        match decoded {
            Some(c) => {
                rest = &rest[width..];
                let mut lower = c.to_lowercase();
                // Go uses the simple mapping, one rune out; Rust's full mapping differs only
                // for U+0130, which Go maps to 'i'.
                let mapped = match (lower.next(), lower.next()) {
                    (Some(l), None) => l,
                    _ if c == '\u{130}' => 'i',
                    _ => c,
                };
                out.extend_from_slice(mapped.encode_utf8(&mut buf).as_bytes());
            }
            None => {
                rest = &rest[1..];
                out.extend_from_slice('\u{fffd}'.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out
}

fn nanos(ns: i64) -> Duration {
    Duration::from_nanos(u64::try_from(ns).unwrap_or(0))
}

/// Port of `validateInputs` (plus the lowercasing in `parseArgs`). Checks run in Go's order and
/// stop at the first failure.
pub(crate) fn validate(raw: RawConfig, target: TargetOs) -> Result<Config, ValidationError> {
    if raw.version {
        return Ok(Config::Version {
            json: raw.json,
            generator: raw.generator,
        });
    }
    if !raw.inspect.is_empty() {
        // Go walks a map here, so its choice among several flags is random; this reports the
        // first in command-line order (`DEV-inspect-conflict-order`).
        if let Some(name) = raw
            .explicit
            .iter()
            .find(|&&n| n != "inspect" && n != "json")
        {
            return invalid(format!("--inspect cannot be combined with --{name}"));
        }
        return Ok(Config::Inspect {
            path: raw.inspect,
            json: raw.json,
        });
    }
    if raw.allow_inherited_windows_acl && target != TargetOs::Windows {
        return invalid("--allow-inherited-windows-acl is only valid on Windows");
    }
    let generator = match raw.generator.as_slice() {
        b"" => Generator::Empty,
        b"segmented" => Generator::Segmented,
        b"independent" => Generator::Independent,
        _ => return invalid("generator must be segmented or independent"),
    };
    if raw.timeout_ns < 0 {
        return invalid("timeout must not be negative");
    }
    if raw.benchmark_ns > 0 && (raw.timeout_ns > 0 || raw.max_attempts > 0) {
        return invalid("benchmark cannot be combined with search limits");
    }
    if raw.save_retry_timeout_ns < 0 {
        return invalid("save retry timeout must not be negative");
    }
    if (raw.dry_run || raw.benchmark_ns > 0)
        && (!raw.fallback_out.is_empty() || raw.save_retry_timeout_ns != 0)
    {
        return invalid("save recovery options require saving mode");
    }
    if raw.benchmark_ns < 0 {
        return invalid("benchmark duration must not be negative");
    }
    let prefix = go_to_lower(&raw.prefix);
    let postfix = go_to_lower(&raw.postfix);
    if raw.benchmark_ns > 0 {
        if !prefix.is_empty() || !postfix.is_empty() {
            return invalid("--benchmark cannot be combined with --prefix or --postfix");
        }
        if raw.dry_run {
            return invalid("--benchmark cannot be combined with --dry-run");
        }
        if raw.include_private_exports {
            return invalid("--benchmark cannot be combined with --include-private-exports");
        }
    } else if let Err(e) = validate_patterns(&prefix, &postfix) {
        return invalid(e.to_string());
    }
    let workers = match usize::try_from(raw.workers) {
        Ok(w) if w >= 1 => w,
        _ => return invalid("workers must be at least 1"),
    };
    if workers > MAX_WORKERS {
        return invalid(format!("workers must not exceed {MAX_WORKERS}"));
    }
    if raw.dry_run && raw.include_private_exports {
        return invalid("--include-private-exports cannot be used with --dry-run");
    }
    Ok(Config::Run(RunConfig {
        prefix,
        postfix,
        workers,
        out: raw.out,
        fallback_out: (!raw.fallback_out.is_empty()).then_some(raw.fallback_out),
        generator,
        timeout: nanos(raw.timeout_ns),
        save_retry_timeout: nanos(raw.save_retry_timeout_ns),
        max_attempts: raw.max_attempts,
        benchmark: (raw.benchmark_ns > 0).then(|| nanos(raw.benchmark_ns)),
        dry_run: raw.dry_run,
        include_private_exports: raw.include_private_exports,
        allow_inherited_windows_acl: raw.allow_inherited_windows_acl,
        allow_weak_output_protection: raw.allow_weak_output_protection,
        json: raw.json,
    }))
}

// ---------------------------------------------------------------------------------------
// Error output (Go: `flag` printing in `failf`, then `main`)
// ---------------------------------------------------------------------------------------

pub(crate) enum CliError {
    Parse(ParseError),
    Validation(ValidationError),
}

impl CliError {
    pub(crate) fn exit_code(&self) -> u8 {
        EXIT_USAGE
    }
}

/// Writes exactly what Go writes to stderr for an exit-2 error:
/// a flag error is `<message>\n`, the usage text, then `Error: <message>\n`;
/// a positional or validation error is only `Error: <message>\n`.
pub(crate) fn render_error(
    err: &CliError,
    default_workers: usize,
    w: &mut impl Write,
) -> io::Result<()> {
    let (message, with_usage): (&[u8], bool) = match err {
        CliError::Parse(e) => (e.message(), matches!(e, ParseError::Flag(_))),
        CliError::Validation(e) => (e.0.as_bytes(), false),
    };
    let mut out = Vec::new();
    if with_usage {
        out.extend_from_slice(message);
        out.push(b'\n');
        out.extend_from_slice(usage_text(default_workers).as_bytes());
    }
    out.extend_from_slice(b"Error: ");
    out.extend_from_slice(message);
    out.push(b'\n');
    w.write_all(&out)
}

// The expected texts below come from REFERENCE_FACTS-style observations of the reference
// binary (main at 5bbe76e). Besides these tables, 8,000 random argument vectors were
// compared with it byte for byte on stderr (parse errors with usage, validation errors,
// help, positional errors) and on exit status 2 versus not 2.
#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    /// Parse and validate on a non-Windows target; `Ok(config)` or the stderr text Go prints.
    fn run(args: &[&str]) -> Result<Config, String> {
        run_on(args, TargetOs::Other)
    }

    fn run_on(args: &[&str], target: TargetOs) -> Result<Config, String> {
        match parse(&os(args), 8) {
            Err(e) => Err(rendered(CliError::Parse(e))),
            Ok(Parsed::Help) => Err("help".to_owned()),
            Ok(Parsed::Raw(raw)) => {
                validate(raw, target).map_err(|e| rendered(CliError::Validation(e)))
            }
        }
    }

    fn rendered(e: CliError) -> String {
        let mut out = Vec::new();
        render_error(&e, 8, &mut out).expect("write to a Vec");
        String::from_utf8_lossy(&out).into_owned()
    }

    fn raw(args: &[&str]) -> RawConfig {
        match parse(&os(args), 8) {
            Ok(Parsed::Raw(raw)) => raw,
            _ => panic!("expected a raw config for {args:?}"),
        }
    }

    fn run_config(args: &[&str]) -> RunConfig {
        match run(args) {
            Ok(Config::Run(c)) => c,
            _ => panic!("expected a run config for {args:?}"),
        }
    }

    /// The validation message of `args`, without the `Error: ` framing.
    fn failure(args: &[&str]) -> String {
        let text = run(args).err().expect("expected an error");
        let line = text.lines().last().expect("an error line");
        line.strip_prefix("Error: ")
            .expect("Error: prefix")
            .to_owned()
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

    #[test]
    fn grammar_errors_print_go_messages_then_usage_then_error_line() {
        // (arguments, message). Observed: `lxmf-vanity <arguments>` exit 2.
        let rows: &[(&[&str], &str)] = &[
            (&["---prefix", "a"], "bad flag syntax: ---prefix"),
            (&["-=x"], "bad flag syntax: -=x"),
            (&["--=x"], "bad flag syntax: --=x"),
            (&["--workers"], "flag needs an argument: -workers"),
            (&["--prefix", "a", "--out"], "flag needs an argument: -out"),
            (&["--nope"], "flag provided but not defined: -nope"),
            (&["-nope=3"], "flag provided but not defined: -nope"),
            (&["--Prefix", "a"], "flag provided but not defined: -Prefix"),
            (
                &["--version", "--nope"],
                "flag provided but not defined: -nope",
            ),
            (
                &["--benchmark", "1d"],
                "invalid value \"1d\" for flag -benchmark: parse error",
            ),
            (
                &["--benchmark", "5"],
                "invalid value \"5\" for flag -benchmark: parse error",
            ),
            (
                &["--benchmark", "9223372036854775808ns"],
                "invalid value \"9223372036854775808ns\" for flag -benchmark: parse error",
            ),
            (
                &["--timeout", ""],
                "invalid value \"\" for flag -timeout: parse error",
            ),
            (
                &["--max-attempts", "-1"],
                "invalid value \"-1\" for flag -max-attempts: parse error",
            ),
            (
                &["--max-attempts", "18446744073709551616"],
                "invalid value \"18446744073709551616\" for flag -max-attempts: value out of range",
            ),
            (
                &["--workers", "08"],
                "invalid value \"08\" for flag -workers: parse error",
            ),
            (
                &["--workers=1__0"],
                "invalid value \"1__0\" for flag -workers: parse error",
            ),
            (
                &["--workers", "99999999999999999999"],
                "invalid value \"99999999999999999999\" for flag -workers: value out of range",
            ),
            (
                &["--workers", "x\ny"],
                "invalid value \"x\\ny\" for flag -workers: parse error",
            ),
            // Booleans have their own wording in Go's flag package.
            (
                &["--json=maybe"],
                "invalid boolean value \"maybe\" for -json: parse error",
            ),
            (
                &["--dry-run="],
                "invalid boolean value \"\" for -dry-run: parse error",
            ),
            (
                &["-version=yes"],
                "invalid boolean value \"yes\" for -version: parse error",
            ),
        ];
        for &(args, message) in rows {
            let want = format!("{message}\n{USAGE_8}Error: {message}\n");
            assert_eq!(run(args).err().as_deref(), Some(want.as_str()), "{args:?}");
        }
    }

    #[test]
    fn positional_arguments_give_an_error_line_without_usage() {
        let rows: &[(&[&str], &str)] = &[
            (
                &["--json", "false", "--benchmark", "1ms"],
                "unexpected positional arguments [\"false\" \"--benchmark\" \"1ms\"]; all options must use flags",
            ),
            (
                &["--", "--prefix", "a"],
                "unexpected positional arguments [\"--prefix\" \"a\"]; all options must use flags",
            ),
            (
                &["-"],
                "unexpected positional arguments [\"-\"]; all options must use flags",
            ),
            (
                &["x", "-h"],
                "unexpected positional arguments [\"x\" \"-h\"]; all options must use flags",
            ),
            (
                &["--version", "a b", "\u{e9}"],
                "unexpected positional arguments [\"a b\" \"\u{e9}\"]; all options must use flags",
            ),
            (
                &[""],
                "unexpected positional arguments [\"\"]; all options must use flags",
            ),
            (
                &["--prefix", "a", "--", "--"],
                "unexpected positional arguments [\"--\"]; all options must use flags",
            ),
        ];
        for &(args, message) in rows {
            let want = format!("Error: {message}\n");
            assert_eq!(run(args).err().as_deref(), Some(want.as_str()), "{args:?}");
        }
    }

    #[test]
    fn double_dash_alone_is_consumed_and_leaves_validation_to_run() {
        assert_eq!(
            failure(&["--"]),
            "at least one of --prefix or --postfix must be specified"
        );
    }

    #[test]
    fn validation_messages_and_order_match_reference_facts_5() {
        let rows: &[(&[&str], &str)] = &[
            (&["--version", "--prefix", "zz"], "ok"),
            (
                &["--inspect", "f", "--json", "--timeout", "-1s"],
                "--inspect cannot be combined with --timeout",
            ),
            (&["--inspect", "f", "--json"], "ok"),
            (&["--inspect=", "--prefix", "a"], "ok"),
            (
                &["--allow-inherited-windows-acl", "--prefix", "a"],
                "--allow-inherited-windows-acl is only valid on Windows",
            ),
            (
                &["--generator", "x", "--prefix", "a"],
                "generator must be segmented or independent",
            ),
            (
                &["--generator", "Segmented", "--prefix", "a"],
                "generator must be segmented or independent",
            ),
            (&["--generator=", "--prefix", "a"], "ok"),
            (&["--generator=independent", "--prefix", "a"], "ok"),
            (
                &["--timeout", "-1s", "--prefix", "a"],
                "timeout must not be negative",
            ),
            (
                &["--timeout", "-1ns", "--prefix", "a"],
                "timeout must not be negative",
            ),
            (&["--timeout", "-0", "--prefix", "a"], "ok"),
            (
                &["--benchmark", "1s", "--timeout", "1s"],
                "benchmark cannot be combined with search limits",
            ),
            (
                &["--benchmark", "1s", "--max-attempts", "1"],
                "benchmark cannot be combined with search limits",
            ),
            (
                &["--save-retry-timeout", "-1s", "--prefix", "a"],
                "save retry timeout must not be negative",
            ),
            (
                &["--dry-run", "--fallback-out", "x", "--prefix", "a"],
                "save recovery options require saving mode",
            ),
            (
                &["--benchmark", "1s", "--save-retry-timeout", "1s"],
                "save recovery options require saving mode",
            ),
            (
                &["--benchmark", "-1s"],
                "benchmark duration must not be negative",
            ),
            (
                &["--benchmark", "1s", "--prefix", "a"],
                "--benchmark cannot be combined with --prefix or --postfix",
            ),
            (
                &["--benchmark", "1s", "--postfix", "a"],
                "--benchmark cannot be combined with --prefix or --postfix",
            ),
            (
                &["--benchmark", "1s", "--dry-run"],
                "--benchmark cannot be combined with --dry-run",
            ),
            (
                &["--benchmark", "1s", "--include-private-exports"],
                "--benchmark cannot be combined with --include-private-exports",
            ),
            (
                &["--benchmark", "0"],
                "at least one of --prefix or --postfix must be specified",
            ),
            (
                &[],
                "at least one of --prefix or --postfix must be specified",
            ),
            (
                &["--prefix", &"a".repeat(33)],
                "prefix must be 1-32 hex characters",
            ),
            (
                &["--postfix", &"a".repeat(33)],
                "postfix must be 1-32 hex characters",
            ),
            (
                &["--prefix", "zz"],
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                &["--postfix", "zz"],
                "postfix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                &["--prefix", "a b"],
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                &["--prefix", &"a".repeat(17), "--postfix", &"b".repeat(16)],
                "combined prefix and postfix length must not exceed 32 hex characters",
            ),
            (
                &["--prefix", &"A".repeat(16), "--postfix", &"B".repeat(16)],
                "ok",
            ),
            (
                &["--prefix", "a", "--workers", "0"],
                "workers must be at least 1",
            ),
            (
                &["--prefix", "a", "--workers", "-1"],
                "workers must be at least 1",
            ),
            (
                &["--benchmark", "1ms", "--workers=1_000"],
                "workers must not exceed 256",
            ),
            (&["--benchmark", "1ms", "--workers=256"], "ok"),
            (
                &["--prefix", "a", "--dry-run", "--include-private-exports"],
                "--include-private-exports cannot be used with --dry-run",
            ),
            // First failing check wins.
            (
                &["--generator", "x", "--timeout", "-1s"],
                "generator must be segmented or independent",
            ),
            (
                &["--timeout", "-1s", "--workers", "0"],
                "timeout must not be negative",
            ),
            (
                &["--workers", "0", "--prefix", "zz"],
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                &["--prefix", "zz", "--workers", "0"],
                "prefix must contain only hex characters [0-9a-fA-F]",
            ),
            (
                &[
                    "--prefix",
                    "a",
                    "--workers",
                    "0",
                    "--dry-run",
                    "--include-private-exports",
                ],
                "workers must be at least 1",
            ),
        ];
        for &(args, want) in rows {
            match (run(args), want) {
                (Ok(_), "ok") => {}
                (Ok(_), _) => panic!("{args:?} should fail with {want:?}"),
                (Err(text), "ok") => panic!("{args:?} should pass, got {text:?}"),
                (Err(text), _) => assert_eq!(text, format!("Error: {want}\n"), "{args:?}"),
            }
        }
    }

    #[test]
    fn windows_accepts_the_acl_flag() {
        let r = run_on(
            &["--allow-inherited-windows-acl", "--prefix", "a"],
            TargetOs::Windows,
        );
        assert!(matches!(r, Ok(Config::Run(c)) if c.allow_inherited_windows_acl));
    }

    #[test]
    fn version_skips_validation_and_keeps_the_raw_generator() {
        // Go: `--version --generator foo --json` succeeds and the JSON result says "foo".
        match run(&[
            "--version",
            "--generator",
            "foo",
            "--json",
            "--workers",
            "0",
            "--timeout",
            "-5s",
        ]) {
            Ok(Config::Version { json, generator }) => {
                assert!(json);
                assert_eq!(generator, b"foo");
            }
            _ => panic!("expected a version config"),
        }
        assert!(matches!(
            run(&["--version=false", "--prefix", "a"]),
            Ok(Config::Run(_))
        ));
    }

    #[test]
    fn inspect_reports_the_first_conflicting_flag_in_command_line_order() {
        // `DEV-inspect-conflict-order`: Go reports a random one of the conflicting flags.
        assert_eq!(
            failure(&["--inspect", "f", "--dry-run", "--prefix", "a"]),
            "--inspect cannot be combined with --dry-run"
        );
        assert_eq!(
            failure(&["--prefix", "a", "--inspect", "f", "--dry-run"]),
            "--inspect cannot be combined with --prefix"
        );
        // json is the only allowed companion; repeats of inspect do not conflict.
        assert!(matches!(
            run(&["--json", "--inspect", "a", "--inspect", "b"]),
            Ok(Config::Inspect { .. })
        ));
        // `--inspect=false`-style values are not booleans: the value is a path.
        assert!(matches!(
            run(&["--inspect=x", "--json=0"]),
            Ok(Config::Inspect { json: false, .. })
        ));
    }

    #[test]
    fn a_run_config_carries_typed_validated_values() {
        let c = run_config(&[
            "--prefix",
            "AbC",
            "--postfix",
            "F0",
            "--workers",
            "0x10",
            "--out",
            "o",
            "--fallback-out",
            "fb",
            "--timeout",
            "1.5s",
            "--save-retry-timeout",
            "2m",
            "--max-attempts",
            "1_000",
            "--json",
        ]);
        assert_eq!(
            (c.prefix.as_slice(), c.postfix.as_slice()),
            (&b"abc"[..], &b"f0"[..])
        );
        assert_eq!(c.workers, 16);
        assert_eq!(c.out, OsString::from("o"));
        assert_eq!(c.fallback_out, Some(OsString::from("fb")));
        assert_eq!(c.timeout, Duration::from_millis(1500));
        assert_eq!(c.save_retry_timeout, Duration::from_secs(120));
        assert_eq!(c.max_attempts, 1000);
        assert_eq!(c.generator, Generator::Segmented);
        assert!(c.benchmark.is_none() && c.json && !c.dry_run);
        let c = run_config(&["--benchmark", "2s", "--generator="]);
        assert_eq!(c.benchmark, Some(Duration::from_secs(2)));
        assert_eq!(c.generator, Generator::Empty);
        assert_eq!(c.generator.as_bytes(), b"");
        assert_eq!(c.out, OsString::from("identity"));
        assert_eq!(c.fallback_out, None);
        // An explicit empty fallback is the same as none, as in Go.
        assert_eq!(
            run_config(&["--prefix", "a", "--fallback-out="]).fallback_out,
            None
        );
    }

    #[test]
    fn default_workers_come_from_the_caller_and_are_in_range() {
        assert_eq!(raw(&[]).workers, 8);
        let n = default_workers();
        assert!((1..=MAX_WORKERS).contains(&n));
    }

    #[test]
    fn patterns_are_lowercased_like_go_before_validation() {
        assert_eq!(go_to_lower(b"AbC123"), b"abc123");
        // U+212A KELVIN SIGN lowercases to ASCII 'k': 3 bytes become 1, so 11 of them (33 bytes)
        // pass the length check and fail the hex check, as in Go.
        let kelvin = "\u{212a}".repeat(11);
        assert_eq!(
            failure(&["--prefix", &kelvin]),
            "prefix must contain only hex characters [0-9a-fA-F]"
        );
        // U+0130 lowercases to 'i' in Go (2 bytes become 1).
        let dotted = "\u{130}".repeat(17);
        assert_eq!(
            failure(&["--prefix", &dotted]),
            "prefix must contain only hex characters [0-9a-fA-F]"
        );
        // Plain non-ASCII text of 33 bytes is too long.
        let e_acute = "\u{e9}".repeat(17);
        assert_eq!(
            failure(&["--prefix", &e_acute]),
            "prefix must be 1-32 hex characters"
        );
        // Pins `DEV-pattern-lowercase-unicode`: Rust lowercases U+A7DD (3 bytes) to U+0277 (2
        // bytes); Go 1.27.4 leaves it unchanged.
        assert_eq!(go_to_lower("\u{a7dd}".as_bytes()), "\u{277}".as_bytes());
        // Each invalid byte grows to U+FFFD (3 bytes), so 11 of them exceed 32 bytes.
        assert_eq!(go_to_lower(&[0xff; 11]).len(), 33);
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

    #[test]
    fn errors_exit_with_status_2() {
        let e = CliError::Validation(ValidationError("x".to_owned()));
        assert_eq!(e.exit_code(), 2);
    }
}
