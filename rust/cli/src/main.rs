//! Command-line interface of lxmf-vanity.
//!
//! This build implements `--inspect`, `--help` and `--version`; every other mode stops with an
//! error until the search and save paths exist. The startup order is Go's (`main` and
//! `runWithDependencies`), with the FIPS policy of decision R-4 inserted where Go's self-test fails:
//!
//! 1. an unknown `GODEBUG` `fips140` value: exit 2;
//! 2. argument parsing: help, parse and validation errors;
//! 3. `--version`;
//! 4. best-effort process hardening;
//! 5. the FIPS policy and the known-answer self-test (a failure is a normal `failed` result);
//! 6. inspection, or the stop for a mode that is not implemented yet.
//!
//! Signal handling belongs to the search path and is not installed here.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use lxmf_vanity_core::selftest::self_test;

use crate::args::{CliError, Config, Parsed, TargetOs};
use crate::console::{CLOSE_TIMEOUT, Console};
use crate::godebug::FipsSetting;
use crate::public_result::{PublicResult, write_result};
use crate::target_path::{go_error_text, path_bytes};

mod args;
mod console;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the private-export encodings are for the sidecar (P3-02)"
    )
)]
mod encode;
mod godebug;
mod goparse;
mod goquote;
mod inspect;
mod jsonw;
mod public_result;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the sidecar file is written by the save path (P3-02)"
    )
)]
mod sidecar;
mod target_path;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the search and save texts are for P2-03 and P3-05"
    )
)]
mod textfmt;
mod version;

/// The inspection warning for an X25519 half that was not clamped (Go: `runWithDependencies`).
const UNMASKED_WARNING: &[u8] =
    b"Warning: unmasked X25519 input; imported bytes were preserved and no file was written.\n";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    ExitCode::from(start(&args))
}

/// A write straight to stderr, for what happens before the console exists. A failed write has
/// nowhere else to go.
fn direct_stderr(bytes: &[u8]) {
    let _ = io::stderr().write_all(bytes);
}

/// Go's `%q`, as text (its output is always valid UTF-8).
fn quoted(value: &[u8]) -> String {
    let mut out = Vec::new();
    goquote::quote_into(&mut out, value);
    String::from_utf8_lossy(&out).into_owned()
}

fn start(args: &[OsString]) -> u8 {
    // 1. Go's runtime fails before `main` on an unknown value, `--help` and `--version` included.
    let fips = godebug::fips_setting_from_env();
    if let Err(unknown) = godebug::check_known(&fips) {
        direct_stderr(format!("Error: {}\n", unknown.message(quoted)).as_bytes());
        return godebug::EXIT_UNKNOWN;
    }
    // 2. Help, parse errors and validation errors never write to stdout.
    let workers = args::default_workers();
    let usage_error = |error: CliError| {
        let _ = args::render_error(&error, workers, &mut io::stderr());
        error.exit_code()
    };
    let config = match args::parse(args, workers) {
        Err(error) => return usage_error(CliError::Parse(error)),
        Ok(Parsed::Help) => {
            direct_stderr(args::usage_text(workers).as_bytes());
            return 0;
        }
        Ok(Parsed::Raw(raw)) => match args::validate(raw, TargetOs::host()) {
            Ok(config) => config,
            Err(error) => return usage_error(CliError::Validation(error)),
        },
    };
    match config {
        // 3.
        Config::Version { json, generator } => version_command(json, &generator),
        Config::Inspect { path, json } => {
            harden();
            // Inspection reports the default generator: any explicit flag besides --json was refused.
            with_console(&fips, json, b"segmented", |console, public| {
                inspect_command(console, public, json, &path)
            })
        }
        Config::Run(config) => {
            harden();
            with_console(
                &fips,
                config.json,
                config.generator.as_bytes(),
                |console, public| {
                    let mode = if config.benchmark.is_some() {
                        "benchmark"
                    } else if config.dry_run {
                        "dry-run"
                    } else {
                        "search"
                    };
                    let message = format!("this build does not implement {mode} yet");
                    fail(console, config.json, public, message.as_bytes())
                },
            )
        }
    }
}

/// 4. Best effort: a failure is a notice, written directly to stderr, and the run goes on.
fn harden() {
    if let Err(error) = lxmf_vanity_platform::harden_process() {
        // Go prints a `syscall.Errno`: lowercase, no "(os error N)", errors joined by newlines.
        let text = go_error_text(&error.to_string());
        direct_stderr(
            format!("Notice: best-effort process hardening unavailable: {text}\n").as_bytes(),
        );
    }
}

/// Port of `run` for `--version`: no console, no hardening, no self-test.
fn version_command(json: bool, generator: &[u8]) -> u8 {
    let mut result = PublicResult::new(generator);
    result.status = "version";
    match deliver(json.then_some(&result), version::version_text().as_bytes()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// The part of `runWithDependencies` every mode shares: the console, the policy and self-test
/// checks, and closing the console at the end (Go's `defer c.close`).
fn with_console(
    fips: &FipsSetting,
    json: bool,
    generator: &[u8],
    body: impl FnOnce(&Console, &mut PublicResult) -> u8,
) -> u8 {
    let console = match Console::new(io::stderr()) {
        Ok(console) => console,
        Err(error) => {
            direct_stderr(format!("Error: cannot start the status console: {error}\n").as_bytes());
            return 1;
        }
    };
    let mut public = PublicResult::new(generator);
    let code = match startup_checks(fips) {
        Err(message) => fail(&console, json, &mut public, message.as_bytes()),
        Ok(()) => body(&console, &mut public),
    };
    console.close(CLOSE_TIMEOUT);
    code
}

/// 5. The FIPS policy (R-4), then the known-answer self-test, before any file is looked at.
fn startup_checks(fips: &FipsSetting) -> Result<(), String> {
    godebug::check_runtime(fips).map_err(|e| e.to_string())?;
    self_test().map_err(|e| e.to_string())
}

/// Port of the `fail` closure: `Error: <message>` through the console; with `--json` the public
/// result follows, with `error` set, once the console is closed. Always exit status 1.
fn fail(console: &Console, json: bool, public: &mut PublicResult, message: &[u8]) -> u8 {
    let mut line = b"Error: ".to_vec();
    line.extend_from_slice(message);
    line.push(b'\n');
    console.status(line);
    if json {
        public.error = message.to_vec();
        console.close(CLOSE_TIMEOUT);
        // Nothing more can be done if this write fails; the status is 1 either way.
        let _ = deliver(Some(public), b"");
    }
    1
}

/// 6. Port of the inspection branch of `runWithDependencies`.
fn inspect_command(
    console: &Console,
    public: &mut PublicResult,
    json: bool,
    path: &std::ffi::OsStr,
) -> u8 {
    let found = match inspect::inspect_identity(path) {
        Ok(found) => found,
        Err(error) => return fail(console, json, public, &error.message()),
    };
    let mut text = Vec::new();
    sidecar::write_public_identity_info(&mut text, &found.public, &path_bytes(&found.name));
    text.extend_from_slice(sidecar::PUBLIC_ONLY_LINE);
    public.status = "inspected";
    public.identity(&found.public);
    if found.unmasked {
        console.status(UNMASKED_WARNING.to_vec());
    }
    // The result goes out only after the status queue is closed, as in Go.
    console.close(CLOSE_TIMEOUT);
    match deliver(json.then_some(&*public), &text) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Writes the JSON result (or `text`) to stdout, as `writeResult` does. A failed or short write
/// is an error.
///
/// On Unix this writes through a duplicate of descriptor 1, not through `io::stdout()`: Rust's
/// stdout treats a closed descriptor (EBADF) as success, while Go reports it, and delivering the
/// result is what the exit status stands for.
#[cfg(unix)]
fn deliver(result: Option<&PublicResult>, text: &[u8]) -> io::Result<()> {
    use std::os::fd::AsFd;
    let mut out = std::fs::File::from(io::stdout().as_fd().try_clone_to_owned()?);
    write_result(&mut out, result, text)
}

/// On Windows, `io::stdout()` is the handle that converts text for a console; it is locked for
/// the whole write and flushed.
#[cfg(windows)]
fn deliver(result: Option<&PublicResult>, text: &[u8]) -> io::Result<()> {
    /// `write_result` makes one `write` call; the line buffer may take only part of it.
    struct WriteAll<W: Write>(W);
    impl<W: Write> Write for WriteAll<W> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write_all(buf)?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    let mut out = WriteAll(io::stdout().lock());
    write_result(&mut out, result, text)?;
    out.flush()
}
