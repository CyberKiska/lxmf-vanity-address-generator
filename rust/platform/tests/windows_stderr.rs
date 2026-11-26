#![cfg(windows)]
#![expect(clippy::unwrap_used, reason = "test code")]
//! `stderr_is_char_device` in a child process: true for `NUL`, false for a
//! pipe. The child is this test binary, run with a marker variable. A real
//! console cannot be set up from an automated run; it is covered by P3-03.

use lxmf_vanity_platform::stderr_is_char_device;
use std::process::{Command, Stdio};

const MARKER: &str = "LXMF_STDERR_PROBE";

// Not a test of its own: with the marker set it reports and the parent reads
// the line; without it, it does nothing.
#[test]
fn stderr_probe_child() {
    if std::env::var_os(MARKER).is_some() {
        println!("char_device={}", stderr_is_char_device());
    }
}

fn probe(stderr: Stdio) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "stderr_probe_child", "--nocapture"])
        .env(MARKER, "1")
        .stdout(Stdio::piped())
        .stderr(stderr)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn stderr_on_nul_is_a_char_device() {
    assert!(probe(Stdio::null()).contains("char_device=true"));
}

#[test]
fn stderr_on_a_pipe_is_not_a_char_device() {
    assert!(probe(Stdio::piped()).contains("char_device=false"));
}

#[test]
fn stderr_on_a_file_is_not_a_char_device() {
    let path = std::env::temp_dir().join(format!("lxmf-p1-05-stderr-{}", std::process::id()));
    let file = std::fs::File::create(&path).unwrap();
    let out = probe(Stdio::from(file));
    let _ = std::fs::remove_file(&path);
    assert!(out.contains("char_device=false"));
}
