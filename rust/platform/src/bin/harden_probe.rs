//! Test helper: hardens itself, then prints what the OS reports, one
//! `key=value` per line. Used only by `tests/unix_harden.rs`; it is the one
//! process allowed to call `harden_process` outside `main`.

#[cfg(unix)]
use lxmf_vanity_platform::harden_process;
#[cfg(unix)]
use rustix::process::{Resource, getrlimit};
#[cfg(unix)]
use std::io::Write;
use std::process::ExitCode;

#[cfg(not(unix))]
fn main() -> ExitCode {
    ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> ExitCode {
    let before = getrlimit(Resource::Core);
    if let Err(err) = harden_process() {
        let _ = writeln!(std::io::stderr(), "harden failed: {err}");
        return ExitCode::FAILURE;
    }
    let after = getrlimit(Resource::Core);
    let mut out = std::io::stdout();
    let show = |v: Option<u64>| v.map_or_else(|| "unlimited".to_string(), |n| n.to_string());
    #[cfg_attr(
        not(target_os = "linux"),
        expect(unused_mut, reason = "only Linux appends the dumpable line")
    )]
    let mut text = format!(
        "hard_before={}\nsoft={}\nhard={}\n",
        show(before.maximum),
        show(after.current),
        show(after.maximum)
    );
    // PR_GET_DUMPABLE, as Go's test does; /proc/self/status has no such line.
    #[cfg(target_os = "linux")]
    if let Ok(value) = rustix::process::dumpable_behavior() {
        text.push_str(&format!("dumpable={}\n", value as i32));
    }
    if out.write_all(text.as_bytes()).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
