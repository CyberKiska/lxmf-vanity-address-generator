#![expect(clippy::expect_used, reason = "test code")]
//! Process-level tests of `--inspect`, `--help`, `--version` and the startup order.
//!
//! Each test runs the built binary on public fixtures only: the golden vector from the Reticulum
//! reference, written into a directory this file creates and removes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_lxmf-vanity");

/// The version string the binary reports (`LXMF_VANITY_VERSION` at build time, else the package's).
const VERSION: &str = match option_env!("LXMF_VANITY_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

const GOLDEN_ADDRESS: &str = "fae321c442e3c9bdcd7a3e79d850e03c";
const GOLDEN_X25519: &str = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
const GOLDEN_ED25519: &str = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";

const GOLDEN_TEXT: &str = "LXMF Vanity Address Identity\n\
============================\n\
\n\
Address (LXMF): fae321c442e3c9bdcd7a3e79d850e03c\n\
Identity Hash:  aca31af0441d81dbec71e82da0b4b5f5\n\
Full Specifier: <lxmf.delivery.aca31af0441d81dbec71e82da0b4b5f5:fae321c442e3c9bdcd7a3e79d850e03c>\n\
\n\
Public Key (X25519 + Ed25519):\n\
\x20 X25519 Public:  8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f\n\
\x20 Ed25519 Public: 29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n\
\x20 Combined:       8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n\
\n\
Private identity file: \"golden-public-fixture\"\n\
This metadata file contains public information only.\n";

const UNMASKED_WARNING: &str =
    "Warning: unmasked X25519 input; imported bytes were preserved and no file was written.\n";

const NOT_64: &str = "inspection input must be a regular file of exactly 64 bytes";
const NOT_REGULAR: &str = "inspection input must be a regular file";

/// A disposable directory in the system temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lxmf-vanity-cli-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&dir).expect("create the test directory");
        TempDir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Sorted names of the directory's entries.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .expect("list the test directory")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The golden vector's unmasked input (bytes 0x00 to 0x3f) or its masked form.
fn golden_input(masked: bool) -> [u8; 64] {
    let mut bytes: [u8; 64] = std::array::from_fn(|i| u8::try_from(i).expect("below 64"));
    if masked {
        bytes[31] = 0x5f;
    }
    bytes
}

fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_remove("GODEBUG").stdin(Stdio::null());
    cmd
}

fn run(args: &[&str]) -> Output {
    command(args).output().expect("run the binary")
}

fn run_in(dir: &Path, args: &[&str]) -> Output {
    command(args)
        .current_dir(dir)
        .output()
        .expect("run the binary")
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 output")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exit status, not a signal")
}

/// What `--json` prints for a failure of `inspect`: the default result plus `error`.
fn failed_json(error: &str) -> String {
    format!(
        "{{\"status\":\"failed\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\
         \"notices\":[],\"attempts\":0,\"elapsed_seconds\":0,\"generator\":\"segmented\",\
         \"version\":\"{VERSION}\",\"error\":\"{error}\"}}\n"
    )
}

fn golden_json() -> String {
    format!(
        "{{\"status\":\"inspected\",\"address\":\"{GOLDEN_ADDRESS}\",\
         \"identity_hash\":\"aca31af0441d81dbec71e82da0b4b5f5\",\
         \"x25519_public\":\"{GOLDEN_X25519}\",\"ed25519_public\":\"{GOLDEN_ED25519}\",\
         \"public_key\":\"{GOLDEN_X25519}{GOLDEN_ED25519}\",\"verified_files\":[],\
         \"unverified_files\":[],\"deviations\":[],\"notices\":[],\"attempts\":0,\
         \"elapsed_seconds\":0,\"generator\":\"segmented\",\"version\":\"{VERSION}\"}}\n"
    )
}

/// A directory holding the golden vector as `golden-public-fixture`.
fn golden_dir(masked: bool) -> (TempDir, String) {
    let dir = TempDir::new("golden");
    let file = dir.path("golden-public-fixture");
    fs::write(&file, golden_input(masked)).expect("write the fixture");
    let arg = file.to_str().expect("UTF-8 temp path").to_owned();
    (dir, arg)
}

// ---------------------------------------------------------------------------------------
// Inspection: success
// ---------------------------------------------------------------------------------------

#[test]
fn golden_text_is_exact_for_masked_and_unmasked_input() {
    for masked in [true, false] {
        let (_dir, path) = golden_dir(masked);
        let out = run(&["--inspect", &path]);
        assert_eq!(code(&out), 0, "masked={masked}");
        assert_eq!(text(&out.stdout), GOLDEN_TEXT, "masked={masked}");
        // Only an input that needed clamping gets the warning, and only on stderr.
        let want = if masked { "" } else { UNMASKED_WARNING };
        assert_eq!(text(&out.stderr), want, "masked={masked}");
    }
}

#[test]
fn golden_json_is_exact_for_masked_and_unmasked_input() {
    for masked in [true, false] {
        let (_dir, path) = golden_dir(masked);
        let out = run(&["--inspect", &path, "--json"]);
        assert_eq!(code(&out), 0, "masked={masked}");
        assert_eq!(text(&out.stdout), golden_json(), "masked={masked}");
        let want = if masked { "" } else { UNMASKED_WARNING };
        assert_eq!(text(&out.stderr), want, "masked={masked}");
    }
}

#[test]
fn json_flag_order_and_forms_do_not_matter() {
    let (_dir, path) = golden_dir(true);
    for args in [
        vec!["--json", "--inspect", &path],
        vec!["-json=true", "-inspect", &path],
        vec!["--inspect", &path, "--json=T"],
    ] {
        let out = run(&args);
        assert_eq!(text(&out.stdout), golden_json(), "{args:?}");
    }
    // `--json=false` means text.
    let out = run(&["--inspect", &path, "--json=false"]);
    assert_eq!(text(&out.stdout), GOLDEN_TEXT);
}

#[test]
fn inspection_leaves_the_input_and_the_directory_untouched() {
    let (dir, path) = golden_dir(false);
    let before = fs::read(&path).expect("read");
    let modified = fs::metadata(&path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        fs::metadata(&path).expect("metadata").permissions().mode()
    };
    for json in [false, true] {
        let mut args = vec!["--inspect", &path];
        if json {
            args.push("--json");
        }
        assert_eq!(code(&run(&args)), 0);
    }
    assert_eq!(
        fs::read(&path).expect("read"),
        before,
        "the unmasked bytes are kept"
    );
    assert_eq!(
        fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime"),
        modified
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode(),
            mode
        );
    }
    // No sidecar, no temporary file, nothing else.
    assert_eq!(dir.entries(), ["golden-public-fixture"]);
}

#[test]
fn a_relative_path_with_dotdot_is_cleaned_and_only_the_base_name_is_shown() {
    let dir = TempDir::new("relative");
    fs::create_dir(dir.path("a")).expect("mkdir");
    fs::write(dir.path("a/golden-public-fixture"), golden_input(true)).expect("write");
    let out = run_in(&dir.0, &["--inspect", "a/b/../golden-public-fixture"]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), GOLDEN_TEXT);
}

#[test]
fn a_file_name_is_quoted_like_gos_q() {
    let dir = TempDir::new("quoted");
    fs::write(dir.path("my identity"), golden_input(true)).expect("write");
    let out = run_in(&dir.0, &["--inspect", "my identity"]);
    assert_eq!(code(&out), 0);
    assert!(text(&out.stdout).contains("Private identity file: \"my identity\"\n"));
}

// ---------------------------------------------------------------------------------------
// Inspection: rejections
// ---------------------------------------------------------------------------------------

/// Text mode and JSON mode both fail with `message`: exit 1, `Error: <message>` on stderr, and
/// nothing or the failed result on stdout.
fn assert_rejected(args: &[&str], message: &str) {
    let text_out = run(&[&["--inspect"], args].concat());
    assert_eq!(code(&text_out), 1, "{args:?}");
    assert_eq!(text(&text_out.stdout), "", "{args:?}");
    assert_eq!(
        text(&text_out.stderr),
        format!("Error: {message}\n"),
        "{args:?}"
    );
    let json_out = run(&[&["--inspect"], args, &["--json"]].concat());
    assert_eq!(code(&json_out), 1, "{args:?}");
    assert_eq!(text(&json_out.stdout), failed_json(message), "{args:?}");
    assert_eq!(
        text(&json_out.stderr),
        format!("Error: {message}\n"),
        "{args:?}"
    );
}

#[test]
fn wrong_sizes_are_rejected_without_reading_the_content() {
    let dir = TempDir::new("sizes");
    for size in [0usize, 1, 63, 65, 4096] {
        let name = format!("size-{size}");
        fs::write(dir.path(&name), vec![0x41u8; size]).expect("write");
        let path = dir.path(&name);
        assert_rejected(&[path.to_str().expect("UTF-8")], NOT_64);
    }
    assert_eq!(dir.entries().len(), 5, "nothing was created");
}

#[test]
fn a_directory_is_not_a_regular_file() {
    let dir = TempDir::new("directory");
    fs::create_dir(dir.path("folder")).expect("mkdir");
    let path = dir.path("folder");
    assert_rejected(&[path.to_str().expect("UTF-8")], NOT_REGULAR);
}

#[test]
fn paths_that_name_no_file_are_rejected() {
    let dir = TempDir::new("noname");
    fs::create_dir(dir.path("sub")).expect("mkdir");
    for path in [".", "..", "sub/", "sub/.", "sub/..", "./"] {
        let out = run_in(&dir.0, &["--inspect", path]);
        assert_eq!(code(&out), 1, "{path:?}");
        assert_eq!(
            text(&out.stderr),
            "Error: output path must name a file\n",
            "{path:?}"
        );
        assert_eq!(text(&out.stdout), "");
    }
}

#[cfg(unix)]
#[test]
fn a_missing_file_and_a_missing_directory_give_gos_texts() {
    let dir = TempDir::new("missing");
    let out = run_in(&dir.0, &["--inspect", "absent"]);
    assert_eq!(
        text(&out.stderr),
        "Error: statat absent: no such file or directory\n"
    );
    assert_eq!(code(&out), 1);
    let out = run_in(&dir.0, &["--inspect", "nodir/input"]);
    let err = text(&out.stderr);
    assert!(
        err.starts_with("Error: open output directory: open ")
            && err.ends_with("/nodir: no such file or directory\n"),
        "{err}"
    );
    assert_eq!(dir.entries(), Vec::<String>::new(), "nothing was created");
}

#[cfg(unix)]
#[test]
fn a_symlink_is_rejected_even_when_it_points_to_a_valid_identity() {
    let dir = TempDir::new("symlink");
    fs::write(dir.path("real"), golden_input(true)).expect("write");
    std::os::unix::fs::symlink("real", dir.path("link")).expect("symlink");
    std::os::unix::fs::symlink("nowhere", dir.path("dangling")).expect("symlink");
    for name in ["link", "dangling"] {
        let path = dir.path(name);
        assert_rejected(&[path.to_str().expect("UTF-8")], NOT_REGULAR);
    }
}

/// Runs the command; `Err` if it takes longer than `seconds` (the process is killed).
#[cfg(unix)]
fn run_with_deadline(mut cmd: Command, seconds: u64) -> Result<Output, String> {
    use std::io::Read;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("the process did not exit within {seconds} s"));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_end(&mut stdout)
        .expect("read");
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_end(&mut stderr)
        .expect("read");
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(unix)]
#[test]
fn a_fifo_is_rejected_without_blocking() {
    let dir = TempDir::new("fifo");
    let fifo = dir.path("pipe");
    let made = Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|s| s.success()) {
        eprintln!("skipped: mkfifo is not available");
        return;
    }
    let mut cmd = command(&["--inspect", fifo.to_str().expect("UTF-8")]);
    cmd.stdin(Stdio::null());
    let out = run_with_deadline(cmd, 10).expect("a FIFO must not block the open");
    assert_eq!(code(&out), 1);
    assert_eq!(text(&out.stderr), format!("Error: {NOT_REGULAR}\n"));
    assert_eq!(text(&out.stdout), "");
}

#[cfg(unix)]
#[test]
fn a_file_without_read_permission_fails_at_open() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("noperm");
    fs::write(dir.path("secret-input"), golden_input(true)).expect("write");
    fs::set_permissions(dir.path("secret-input"), fs::Permissions::from_mode(0o000))
        .expect("chmod");
    // A process that may read it anyway (root) cannot show the error.
    if fs::File::open(dir.path("secret-input")).is_ok() {
        eprintln!("skipped: permission bits do not apply to this user");
        return;
    }
    let out = run_in(&dir.0, &["--inspect", "secret-input"]);
    assert_eq!(code(&out), 1);
    assert_eq!(
        text(&out.stderr),
        "Error: openat secret-input: permission denied\n"
    );
}

// ---------------------------------------------------------------------------------------
// Help, version and diagnostics
// ---------------------------------------------------------------------------------------

#[test]
fn help_goes_to_stderr_with_exit_0_and_nothing_on_stdout() {
    for flag in ["--help", "-h", "-help"] {
        let out = run(&[flag]);
        assert_eq!(code(&out), 0, "{flag}");
        assert_eq!(text(&out.stdout), "", "{flag}");
        assert!(
            text(&out.stderr).starts_with("Usage of lxmf-vanity:\n"),
            "{flag}"
        );
    }
}

#[test]
fn version_prints_one_line_or_one_json_object() {
    let out = run(&["--version"]);
    assert_eq!(code(&out), 0);
    let line = text(&out.stdout);
    assert!(
        line.starts_with(&format!("lxmf-vanity {VERSION} (")) && line.ends_with(")\n"),
        "{line:?}"
    );
    assert_eq!(line.matches('\n').count(), 1);
    assert_eq!(text(&out.stderr), "");
    let out = run(&["--version", "--json"]);
    assert_eq!(code(&out), 0);
    assert_eq!(
        text(&out.stdout),
        format!(
            "{{\"status\":\"version\",\"verified_files\":[],\"unverified_files\":[],\"deviations\":[],\
             \"notices\":[],\"attempts\":0,\"elapsed_seconds\":0,\"generator\":\"segmented\",\
             \"version\":\"{VERSION}\"}}\n"
        )
    );
}

#[test]
fn version_skips_validation_but_parse_errors_come_first() {
    assert_eq!(code(&run(&["--version", "--prefix", "zz"])), 0);
    let out = run(&["--version", "--nope"]);
    assert_eq!(code(&out), 2);
    assert_eq!(text(&out.stdout), "");
}

#[test]
fn diagnostics_go_to_stderr_and_stdout_stays_empty_even_with_json() {
    // A parse error: the message, the usage text, then `Error: <message>`.
    let out = run(&["--json", "--nope"]);
    assert_eq!(code(&out), 2);
    assert_eq!(text(&out.stdout), "");
    let err = text(&out.stderr);
    assert!(
        err.starts_with("flag provided but not defined: -nope\nUsage of lxmf-vanity:\n"),
        "{err}"
    );
    assert!(
        err.ends_with("Error: flag provided but not defined: -nope\n"),
        "{err}"
    );
    // A validation error and positional arguments: only the `Error:` line.
    for (args, message) in [
        (
            vec!["--inspect", "x", "--prefix", "a", "--json"],
            "--inspect cannot be combined with --prefix",
        ),
        (
            vec!["--json"],
            "at least one of --prefix or --postfix must be specified",
        ),
        (
            vec!["--json", "false", "--benchmark", "1ms"],
            "unexpected positional arguments [\"false\" \"--benchmark\" \"1ms\"]; all options must use flags",
        ),
    ] {
        let out = run(&args);
        assert_eq!(code(&out), 2, "{args:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        assert_eq!(text(&out.stderr), format!("Error: {message}\n"), "{args:?}");
    }
}

#[test]
fn a_mode_that_is_not_implemented_yet_fails_through_the_normal_error_path() {
    for (args, mode) in [
        (vec!["--prefix", "a"], "search"),
        (vec!["--prefix", "a", "--dry-run"], "dry-run"),
        (vec!["--benchmark", "1ms"], "benchmark"),
    ] {
        let message = format!("this build does not implement {mode} yet");
        let out = run(&args);
        assert_eq!(code(&out), 1, "{args:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        assert_eq!(text(&out.stderr), format!("Error: {message}\n"), "{args:?}");
        let mut json_args = args.clone();
        json_args.push("--json");
        let out = run(&json_args);
        assert_eq!(code(&out), 1);
        assert_eq!(text(&out.stdout), failed_json(&message));
    }
}

// ---------------------------------------------------------------------------------------
// FIPS policy and the self-test order
// ---------------------------------------------------------------------------------------

fn run_fips(setting: &str, args: &[&str]) -> Output {
    command(args)
        .env("GODEBUG", setting)
        .output()
        .expect("run the binary")
}

#[test]
fn fips_only_fails_the_self_test_before_the_file_is_looked_at() {
    let dir = TempDir::new("fips-only");
    let path = dir.path("does-not-exist");
    let path = path.to_str().expect("UTF-8");
    let out = run_fips("fips140=only", &["--inspect", path]);
    assert_eq!(code(&out), 1);
    assert_eq!(text(&out.stdout), "");
    let err = text(&out.stderr);
    assert!(
        err.starts_with("Error: self-test failed: X25519 public-key derivation unavailable: "),
        "{err}"
    );
    assert!(
        !err.contains("statat"),
        "the file must not be touched first: {err}"
    );
    let out = run_fips("fips140=only", &["--inspect", path, "--json"]);
    assert_eq!(code(&out), 1);
    let json = text(&out.stdout);
    assert!(json.starts_with("{\"status\":\"failed\","), "{json}");
    assert!(
        json.contains("\"error\":\"self-test failed: X25519 public-key derivation unavailable: ")
    );
    assert!(json.contains("\"attempts\":0,\"elapsed_seconds\":0,"));
}

#[test]
fn fips_on_and_debug_are_refused_and_off_or_rightmost_off_is_normal() {
    let (_dir, path) = golden_dir(true);
    for setting in ["fips140=on", "fips140=debug", "fips140=on,fips140=only"] {
        let out = run_fips(setting, &["--inspect", &path]);
        assert_eq!(code(&out), 1, "{setting}");
        assert_eq!(text(&out.stdout), "", "{setting}");
        assert!(text(&out.stderr).starts_with("Error: "), "{setting}");
    }
    for setting in ["fips140=off", "fips140=", "fips140=only,fips140=off", "x=1"] {
        let out = run_fips(setting, &["--inspect", &path]);
        assert_eq!(code(&out), 0, "{setting}");
        assert_eq!(text(&out.stdout), GOLDEN_TEXT, "{setting}");
    }
}

#[test]
fn an_unknown_fips_value_fails_before_parsing_with_exit_2_for_every_command() {
    for args in [
        vec!["--version"],
        vec!["--help"],
        vec!["--nope"],
        vec!["--version", "--json"],
    ] {
        let out = run_fips("fips140=bogus", &args);
        assert_eq!(code(&out), 2, "{args:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        let err = text(&out.stderr);
        assert!(
            err.starts_with("Error: unrecognized GODEBUG setting fips140=\"bogus\""),
            "{err}"
        );
        assert!(
            !err.contains("panic") && !err.contains("goroutine"),
            "{err}"
        );
    }
}

#[test]
fn version_and_help_work_under_fips_only() {
    for args in [vec!["--version"], vec!["--help"]] {
        let out = run_fips("fips140=only", &args);
        assert_eq!(code(&out), 0, "{args:?}");
    }
}

// ---------------------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_stdout_nobody_reads_is_a_delivery_failure_with_exit_1() {
    let (_dir, path) = golden_dir(true);
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let out = command(&["--inspect", &path])
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("run the binary");
    assert_eq!(
        code(&out),
        1,
        "a closed stdout reader must not look like success"
    );
    assert_eq!(text(&out.stderr), "");
}

/// A pipe that is full, so that the next write to it blocks until someone reads.
#[cfg(unix)]
fn full_pipe() -> (std::io::PipeReader, std::io::PipeWriter) {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mut filler = writer.try_clone().expect("clone");
    let written = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&written);
    // One byte at a time, so that the pipe is full to the last byte when the thread blocks. The
    // thread ends with a broken pipe when the reader is dropped.
    std::thread::spawn(move || {
        while filler.write(&[0u8]).is_ok() {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let mut last = usize::MAX;
    loop {
        std::thread::sleep(Duration::from_millis(300));
        let now = written.load(Ordering::Relaxed);
        if now == last {
            break;
        }
        last = now;
    }
    (reader, writer)
}

// Go: TestRunSavesAndReturnsWithBlockedStderr (the stderr half; the save half is P3's)
#[cfg(unix)]
#[test]
fn a_blocked_stderr_does_not_stop_the_result_or_the_exit() {
    use std::io::Read;
    let (_dir, path) = golden_dir(false); // the unmasked input makes the console write a warning
    let (reader, writer) = full_pipe();
    let started = std::time::Instant::now();
    let mut child = command(&["--inspect", &path])
        .stdout(Stdio::piped())
        .stderr(writer)
        .spawn()
        .expect("spawn");
    let deadline = started + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "blocked stderr hung the process"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read");
    assert_eq!(status.code(), Some(0));
    assert_eq!(stdout, GOLDEN_TEXT);
    drop(reader);
}
