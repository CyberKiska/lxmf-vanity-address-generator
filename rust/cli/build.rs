//! Build script: passes the compiler version and build settings to the crate.
//!
//! It runs `$RUSTC --version` and nothing else: no network, no git, no file
//! writes. Its output depends only on the toolchain and the build settings.
use std::env;
use std::io::{self, Write};
use std::process::{Command, ExitCode};

/// Cfg overrides that would change the entropy or curve backend. The release
/// build must use the defaults, so any of them stops the build.
const FORBIDDEN_CFG: [&str; 3] = [
    "CARGO_CFG_GETRANDOM_BACKEND",
    "CARGO_CFG_CURVE25519_DALEK_BACKEND",
    "CARGO_CFG_CURVE25519_DALEK_BITS",
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // Cargo shows a failed script's stderr; nowhere else to report.
            let _ = writeln!(io::stderr(), "lxmf-vanity build script: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    for name in FORBIDDEN_CFG {
        if env::var_os(name).is_some() {
            return Err(format!(
                "{name} is set (a --cfg override in RUSTFLAGS); backend overrides are not allowed"
            ));
        }
    }
    let rustc = env::var_os("RUSTC").ok_or("RUSTC is not set; build with cargo")?;
    let output = Command::new(&rustc)
        .arg("--version")
        .output()
        .map_err(|e| format!("cannot run `{} --version`: {e}", rustc.to_string_lossy()))?;
    if !output.status.success() {
        return Err(format!("`{} --version` failed", rustc.to_string_lossy()));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "`rustc --version` is not UTF-8")?;
    // "rustc 1.100.0 (0ef1bc386 2026-11-09)": keep only "1.100.0". Anything after
    // it (such as "(Homebrew)") describes the build machine.
    let version = text
        .split_whitespace()
        .nth(1)
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .ok_or_else(|| format!("unexpected `rustc --version` output: {:?}", text.trim()))?;
    let target = env::var("TARGET").map_err(|_| "TARGET is not set; build with cargo")?;
    let opt_level = env::var("OPT_LEVEL").map_err(|_| "OPT_LEVEL is not set; build with cargo")?;

    let mut out = io::stdout().lock();
    let write = |out: &mut dyn Write| -> io::Result<()> {
        writeln!(out, "cargo:rerun-if-changed=build.rs")?;
        writeln!(out, "cargo:rerun-if-env-changed=LXMF_VANITY_VERSION")?;
        writeln!(out, "cargo:rustc-env=LXMF_VANITY_RUSTC_VERSION={version}")?;
        writeln!(out, "cargo:rustc-env=LXMF_VANITY_TARGET={target}")?;
        writeln!(out, "cargo:rustc-env=LXMF_VANITY_OPT_LEVEL={opt_level}")
    };
    write(&mut out).map_err(|e| format!("cannot write to cargo: {e}"))
}
