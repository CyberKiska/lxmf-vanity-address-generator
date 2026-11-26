//! Command-line interface of lxmf-vanity.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

mod godebug;
mod version;

// Not called from `main` until the entry point is wired up.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "argument handling is wired into main later")
)]
mod goquote;

fn main() -> ExitCode {
    // A failed write has nowhere else to go; the exit status carries the result.
    let _ = std::io::stderr()
        .lock()
        .write_all(b"lxmf-vanity: not yet implemented\n");
    ExitCode::from(1)
}
