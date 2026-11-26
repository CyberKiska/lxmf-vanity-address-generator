//! Command-line interface of lxmf-vanity.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

mod godebug;

fn main() -> ExitCode {
    // A failed write has nowhere else to go; the exit status carries the result.
    let _ = std::io::stderr()
        .lock()
        .write_all(b"lxmf-vanity: not yet implemented\n");
    ExitCode::from(1)
}
