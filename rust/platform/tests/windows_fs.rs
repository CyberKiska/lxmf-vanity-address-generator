#![cfg(windows)]
#![expect(clippy::unwrap_used, reason = "test code")]
//! Native Windows tests for the anchored-directory primitives. Run them on a
//! Windows machine with:
//!
//! ```text
//! cargo test -p lxmf-vanity-platform --locked --test windows_fs --test windows_stderr
//! ```
//!
//! Creating symlinks needs Administrator rights or Developer Mode. Hosted CI
//! runners are administrators, so by default a missing privilege fails the
//! symlink tests. A developer machine without it can set
//! `LXMF_ALLOW_SKIP_SYMLINKS=1`; those tests then print `SKIPPED` and return,
//! which is not evidence and never closes the task.

use lxmf_vanity_platform::{AnchoredDir, FileKind, file_meta, set_private_mode, sync_file};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// Small replacement for a temp-dir crate: unique dir, removed on drop.
struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed); // Relaxed: uniqueness only
        let dir = std::env::temp_dir().join(format!("lxmf-p1-05-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        Tmp(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn name(s: &str) -> &OsStr {
    OsStr::new(s)
}

fn kind(err: io::Result<impl std::fmt::Debug>) -> io::ErrorKind {
    err.unwrap_err().kind()
}

/// Symlink creation, or `None` (after printing why) when the machine lacks the
/// privilege and `LXMF_ALLOW_SKIP_SYMLINKS` is set.
#[expect(
    clippy::panic,
    reason = "a missing privilege must fail unless skipping is allowed"
)]
fn try_symlink_file(target: &Path, link: &Path) -> Option<()> {
    match std::os::windows::fs::symlink_file(target, link) {
        Ok(()) => Some(()),
        Err(err) if std::env::var_os("LXMF_ALLOW_SKIP_SYMLINKS").is_some() => {
            let _ = writeln!(
                io::stderr(),
                "SKIPPED (not a pass): cannot create symlinks here: {err}"
            );
            None
        }
        // LXMF_REQUIRE_SYMLINKS is set: a skip must fail the run.
        Err(err) => {
            panic!("cannot create symlinks (set LXMF_ALLOW_SKIP_SYMLINKS=1 to skip): {err}")
        }
    }
}

fn make_junction(link: &Path, target: &Path) {
    // `mklink /J` needs no privilege.
    let status = Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink /J failed: {status:?}");
}

fn remove_junction(link: &Path) {
    // `remove_dir` removes the junction itself, never its contents.
    fs::remove_dir(link).unwrap();
}

#[test]
fn create_exclusive_twice_gives_already_exists() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("a")).unwrap();
    assert_eq!(
        kind(dir.create_exclusive(name("a"))),
        io::ErrorKind::AlreadyExists
    );
}

#[test]
fn create_exclusive_is_case_insensitive_on_default_ntfs() {
    // The default directory is case-insensitive, like Go's OBJ_CASE_INSENSITIVE.
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("Mixed")).unwrap();
    assert_eq!(
        kind(dir.create_exclusive(name("mIXED"))),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(dir.lstat(name("MIXED")).unwrap().kind, FileKind::Regular);
}

#[test]
fn create_exclusive_returns_a_writable_synced_empty_file() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    let mut f = dir.create_exclusive(name("f")).unwrap();
    assert_eq!(file_meta(&f).unwrap().kind, FileKind::Regular);
    f.write_all(b"secret").unwrap();
    sync_file(&f).unwrap();
    drop(f);
    assert_eq!(fs::read(tmp.path().join("f")).unwrap(), b"secret");
}

#[test]
fn link_noreplace_creates_a_second_name_for_the_same_file() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("a"))
        .unwrap()
        .write_all(b"x")
        .unwrap();
    dir.link_noreplace(name("a"), name("b")).unwrap();
    let a = dir.lstat(name("a")).unwrap();
    let b = dir.lstat(name("b")).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(b.size, 1);
}

#[test]
fn link_noreplace_onto_an_existing_name_fails_and_changes_nothing() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("a"))
        .unwrap()
        .write_all(b"first")
        .unwrap();
    dir.create_exclusive(name("b"))
        .unwrap()
        .write_all(b"second")
        .unwrap();
    let before = dir.lstat(name("b")).unwrap();
    assert_eq!(
        kind(dir.link_noreplace(name("a"), name("b"))),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(dir.lstat(name("b")).unwrap(), before);
    assert_eq!(fs::read(tmp.path().join("b")).unwrap(), b"second");
}

#[test]
fn link_noreplace_of_a_missing_source_is_not_found() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    assert_eq!(
        kind(dir.link_noreplace(name("nope"), name("b"))),
        io::ErrorKind::NotFound
    );
}

#[test]
fn symlink_to_a_file_is_reported_not_followed_and_removed_alone() {
    let tmp = Tmp::new();
    fs::write(tmp.path().join("target"), b"data").unwrap();
    if try_symlink_file(Path::new("target"), &tmp.path().join("link")).is_none() {
        return;
    }
    try_symlink_file(Path::new("missing"), &tmp.path().join("dangling")).unwrap();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    assert_eq!(dir.lstat(name("link")).unwrap().kind, FileKind::Symlink);
    assert_eq!(dir.lstat(name("dangling")).unwrap().kind, FileKind::Symlink);
    // Documented: the open fails (ERROR_CANT_ACCESS_FILE, Go's ELOOP); it does
    // not open the link itself or its target.
    assert!(dir.open_read_nofollow(name("link")).is_err());
    assert!(dir.open_rw_nofollow(name("link")).is_err());
    // A name that is a dangling link still counts as existing.
    assert_eq!(
        kind(dir.create_exclusive(name("dangling"))),
        io::ErrorKind::AlreadyExists
    );
    dir.remove(name("link")).unwrap();
    assert!(fs::symlink_metadata(tmp.path().join("link")).is_err());
    assert_eq!(fs::read(tmp.path().join("target")).unwrap(), b"data");
}

#[test]
fn junction_is_reported_not_followed_and_removed_alone() {
    let tmp = Tmp::new();
    let target = tmp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("inside"), b"data").unwrap();
    make_junction(&tmp.path().join("junction"), &target);
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    assert_eq!(dir.lstat(name("junction")).unwrap().kind, FileKind::Symlink);
    assert!(dir.open_read_nofollow(name("junction")).is_err());
    assert_eq!(
        kind(dir.create_exclusive(name("junction"))),
        io::ErrorKind::AlreadyExists
    );
    dir.remove(name("junction")).unwrap();
    assert!(fs::symlink_metadata(tmp.path().join("junction")).is_err());
    assert_eq!(fs::read(target.join("inside")).unwrap(), b"data");
}

#[test]
fn directory_entries_report_directory_and_regular_kinds() {
    let tmp = Tmp::new();
    fs::create_dir(tmp.path().join("sub")).unwrap();
    fs::write(tmp.path().join("f"), b"").unwrap();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    assert_eq!(dir.stat_self().unwrap().kind, FileKind::Directory);
    assert_eq!(dir.lstat(name("sub")).unwrap().kind, FileKind::Directory);
    assert_eq!(dir.lstat(name("f")).unwrap().kind, FileKind::Regular);
    assert_eq!(kind(dir.lstat(name("missing"))), io::ErrorKind::NotFound);
}

#[test]
fn open_on_a_file_path_is_not_a_directory() {
    let tmp = Tmp::new();
    fs::write(tmp.path().join("f"), b"").unwrap();
    assert_eq!(
        kind(AnchoredDir::open(&tmp.path().join("f"))),
        io::ErrorKind::NotADirectory
    );
}

// Go opens the root directory without FILE_SHARE_DELETE (syscall.Open uses
// FILE_SHARE_READ|FILE_SHARE_WRITE), and its own tests skip the rename
// scenario on Windows because "open directory handles may prohibit renaming".
// This pins the same behavior.
#[test]
fn an_open_directory_cannot_be_renamed_like_in_go() {
    let tmp = Tmp::new();
    let sub = tmp.path().join("output");
    fs::create_dir(&sub).unwrap();
    let dir = AnchoredDir::open(&sub).unwrap();
    assert!(fs::rename(&sub, tmp.path().join("moved")).is_err());
    // Everything still works through the handle.
    dir.create_exclusive(name("f")).unwrap();
    assert_eq!(dir.lstat(name("f")).unwrap().kind, FileKind::Regular);
    assert_eq!(
        dir.current_path_identity().unwrap(),
        dir.stat_self().unwrap().id
    );
}

#[test]
fn replaced_path_is_detected_and_operations_stay_in_the_opened_directory() {
    // A junction in the requested path can be retargeted while the directory is
    // open (renaming is blocked, see above). The handle keeps its directory.
    let tmp = Tmp::new();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    let link = tmp.path().join("link");
    make_junction(&link, &a);
    let dir = AnchoredDir::open(&link).unwrap();
    let opened = dir.stat_self().unwrap().id;
    assert_eq!(dir.current_path_identity().unwrap(), opened);

    remove_junction(&link);
    make_junction(&link, &b);

    assert_ne!(dir.current_path_identity().unwrap(), opened);
    assert_eq!(dir.stat_self().unwrap().id, opened);
    dir.create_exclusive(name("owned")).unwrap();
    assert!(a.join("owned").exists());
    assert!(!b.join("owned").exists());
}

#[test]
fn replacing_a_file_by_rename_changes_its_identity() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("a")).unwrap();
    let before = dir.lstat(name("a")).unwrap().id;
    fs::write(tmp.path().join("other"), b"").unwrap();
    fs::rename(tmp.path().join("other"), tmp.path().join("a")).unwrap();
    assert_ne!(dir.lstat(name("a")).unwrap().id, before);
}

#[test]
fn opening_the_same_file_twice_gives_equal_identity() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("a")).unwrap();
    let one = dir.open_read_nofollow(name("a")).unwrap();
    let two = dir.open_rw_nofollow(name("a")).unwrap();
    let id = dir.lstat(name("a")).unwrap().id;
    assert_eq!(file_meta(&one).unwrap().id, id);
    assert_eq!(file_meta(&two).unwrap().id, id);
}

#[test]
fn read_back_through_open_rw_nofollow_then_sync() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    dir.create_exclusive(name("a"))
        .unwrap()
        .write_all(b"abc")
        .unwrap();
    let mut f = dir.open_rw_nofollow(name("a")).unwrap();
    let mut got = Vec::new();
    f.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"abc");
    sync_file(&f).unwrap();
}

#[test]
fn long_directory_path_and_unicode_names_work() {
    let tmp = Tmp::new();
    let mut long = tmp.path().to_path_buf();
    for c in ['a', 'b', 'c'] {
        long.push(c.to_string().repeat(100));
    }
    assert!(long.as_os_str().len() >= 300);
    fs::create_dir_all(&long).unwrap();
    let dir = AnchoredDir::open(&long).unwrap();
    let unicode = "тест-é-日本語-😀.txt";
    dir.create_exclusive(name(unicode)).unwrap();
    assert_eq!(dir.lstat(name(unicode)).unwrap().kind, FileKind::Regular);
    let listed: Vec<_> = fs::read_dir(&long)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(listed, [OsStr::new(unicode).to_os_string()]);
    assert_eq!(
        dir.current_path_identity().unwrap(),
        dir.stat_self().unwrap().id
    );
}

#[test]
fn set_private_mode_clears_the_read_only_attribute() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    let f = dir.create_exclusive(name("a")).unwrap();
    let path = tmp.path().join("a");
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&path, perms).unwrap();
    assert!(fs::metadata(&path).unwrap().permissions().readonly());
    set_private_mode(&f).unwrap();
    assert!(!fs::metadata(&path).unwrap().permissions().readonly());
    set_private_mode(&f).unwrap(); // already clear: no-op
}

#[test]
fn sync_file_succeeds_and_sync_dir_is_unsupported() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    let f = dir.create_exclusive(name("a")).unwrap();
    sync_file(&f).unwrap();
    assert_eq!(kind(dir.sync_dir()), io::ErrorKind::Unsupported);
}

#[test]
fn remove_deletes_an_open_and_a_read_only_file() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    let held = dir.create_exclusive(name("open")).unwrap();
    dir.remove(name("open")).unwrap(); // POSIX semantics: gone while open
    assert_eq!(kind(dir.lstat(name("open"))), io::ErrorKind::NotFound);
    drop(held);

    drop(dir.create_exclusive(name("ro")).unwrap());
    let path = tmp.path().join("ro");
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&path, perms).unwrap();
    dir.remove(name("ro")).unwrap();
    assert_eq!(kind(dir.lstat(name("ro"))), io::ErrorKind::NotFound);
    assert_eq!(kind(dir.remove(name("ro"))), io::ErrorKind::NotFound);
}

#[test]
fn names_that_are_not_one_plain_component_are_rejected() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    for bad in [
        "",
        ".",
        "..",
        "a\\b",
        "a/b",
        "a:b",
        "a:stream",
        "trailing.",
        "trailing ",
        "nul\0byte",
    ] {
        assert_eq!(
            kind(dir.lstat(name(bad))),
            io::ErrorKind::InvalidInput,
            "{bad:?}"
        );
        assert_eq!(
            kind(dir.create_exclusive(name(bad))),
            io::ErrorKind::InvalidInput,
            "{bad:?}"
        );
        assert_eq!(
            kind(dir.remove(name(bad))),
            io::ErrorKind::InvalidInput,
            "{bad:?}"
        );
    }
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
}
