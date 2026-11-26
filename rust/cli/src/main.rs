//! Command-line interface of lxmf-vanity.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the output formats are wired into main later")
)]
mod encode;
mod godebug;
mod version;

// Not called from `main` until the entry point is wired up.
#[expect(dead_code, reason = "argument handling is wired into main later")]
mod args;
mod goparse;
mod goquote;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the output formats are wired into main later")
)]
mod jsonw;

fn main() -> ExitCode {
    // A failed write has nowhere else to go; the exit status carries the result.
    let _ = std::io::stderr()
        .lock()
        .write_all(b"lxmf-vanity: not yet implemented\n");
    ExitCode::from(1)
}
