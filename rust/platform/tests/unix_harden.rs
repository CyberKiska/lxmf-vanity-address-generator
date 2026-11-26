#![cfg(unix)]
//! Hardening is only ever run in the `harden_probe` child, so this test
//! process keeps its own limits. Go: TestHardeningRunsOnlyInDisposableProcess,
//! TestLinuxDumpabilityIsClearedInChild.

use rustix::process::{Resource, getrlimit};
use std::collections::HashMap;
use std::process::Command;

fn show(v: Option<u64>) -> String {
    v.map_or_else(|| "unlimited".to_string(), |n| n.to_string())
}

#[test]
fn probe_has_soft_core_limit_zero_hard_unchanged_and_no_dumpable_on_linux() {
    let before = getrlimit(Resource::Core);
    // Raise only the soft limit first (a login shell often starts at 0), so the
    // probe has something to lower; the hard limit is left as inherited.
    let out = Command::new("sh")
        .args([
            "-c",
            "ulimit -S -c 1024 && exec \"$0\"",
            env!("CARGO_BIN_EXE_harden_probe"),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let values: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    assert_eq!(values["soft"], "0");
    assert_eq!(
        values["hard"],
        show(before.maximum),
        "hard limit must stay as inherited"
    );
    assert_eq!(values["hard_before"], values["hard"]);
    #[cfg(target_os = "linux")]
    assert_eq!(values["dumpable"], "0");
    // The test runner itself was not hardened.
    assert_eq!(getrlimit(Resource::Core), before);
}
