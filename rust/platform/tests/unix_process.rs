#![cfg(unix)]
//! Process queries: effective user id and the character-device check.

use lxmf_vanity_platform::{effective_uid, stderr_is_char_device};
use rustix::process::geteuid;
use std::process::{Command, Stdio};

#[test]
fn effective_uid_matches_the_process() {
    assert_eq!(effective_uid(), Some(geteuid().as_raw()));
}

#[test]
fn child_reports_char_device_for_dev_null_and_not_for_a_pipe() {
    const TEST: &str = "child_reports_char_device_for_dev_null_and_not_for_a_pipe";
    if let Some(expected) = std::env::var_os("LXMF_STDERR_PROBE") {
        // Child mode: the exit status carries the verdict.
        assert_eq!(stderr_is_char_device(), expected == "1");
        return;
    }
    let run = |expect_char: &str, stderr: Stdio| {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST])
            .env("LXMF_STDERR_PROBE", expect_char)
            .stdout(Stdio::null())
            .stderr(stderr)
            .status()
            .unwrap()
            .success()
    };
    assert!(run("1", Stdio::null()), "/dev/null is a character device");
    let (reader, writer) = std::io::pipe().unwrap();
    assert!(run("0", Stdio::from(writer)), "a pipe is not");
    drop(reader);
}
