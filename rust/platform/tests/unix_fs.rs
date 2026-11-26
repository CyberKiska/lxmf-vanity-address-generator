#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "test code")]
//! Anchored-directory and file-identity tests. Each test owns a temporary
//! directory that it removes at the end.

use lxmf_vanity_platform::{AnchoredDir, FileKind, file_meta};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// Small replacement for a temp-dir crate: unique dir, removed on drop.
struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed); // Relaxed: uniqueness only
        let dir = std::env::temp_dir().join(format!("lxmf-p1-04-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        // macOS temp dirs live behind a /var symlink; open() follows it anyway.
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

fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn lstat_reports_symlink_for_valid_and_dangling_links() {
    let tmp = Tmp::new();
    fs::write(tmp.path().join("target"), [0u8; 3]).unwrap();
    symlink("target", tmp.path().join("valid")).unwrap();
    symlink("missing", tmp.path().join("dangling")).unwrap();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    for name in ["valid", "dangling"] {
        assert_eq!(
            dir.lstat(OsStr::new(name)).unwrap().kind,
            FileKind::Symlink,
            "{name}"
        );
    }
    let target = dir.lstat(OsStr::new("target")).unwrap();
    assert_eq!((target.kind, target.size), (FileKind::Regular, 3));
}

#[test]
fn open_read_nofollow_refuses_a_symlink() {
    let tmp = Tmp::new();
    fs::write(tmp.path().join("target"), [0u8; 64]).unwrap();
    symlink("target", tmp.path().join("valid")).unwrap();
    symlink("missing", tmp.path().join("dangling")).unwrap();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    for name in ["valid", "dangling"] {
        assert!(dir.open_read_nofollow(OsStr::new(name)).is_err(), "{name}");
    }
    let mut data = Vec::new();
    dir.open_read_nofollow(OsStr::new("target"))
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data.len(), 64);
}

#[test]
fn fifo_opens_without_blocking_and_is_other() {
    let tmp = Tmp::new();
    mkfifo(&tmp.path().join("fifo"));
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    let (tx, rx) = mpsc::channel();
    // The open runs on its own thread so a regression fails the test by
    // timeout instead of hanging it; the stuck thread dies with the process.
    std::thread::spawn(move || {
        let result = dir
            .open_read_nofollow(OsStr::new("fifo"))
            .and_then(|f| file_meta(&f));
        let _ = tx.send(result.map(|m| m.kind));
    });
    let kind = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("open blocked on a FIFO")
        .unwrap();
    assert_eq!(kind, FileKind::Other);
}

#[test]
fn same_file_has_equal_id_and_atomic_rename_changes_it() {
    let tmp = Tmp::new();
    let path = tmp.path().join("key");
    fs::write(&path, [1u8; 64]).unwrap();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    let a = file_meta(&dir.open_read_nofollow(OsStr::new("key")).unwrap()).unwrap();
    let b = file_meta(&dir.open_read_nofollow(OsStr::new("key")).unwrap()).unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(a.id, dir.lstat(OsStr::new("key")).unwrap().id);
    let old = dir.open_read_nofollow(OsStr::new("key")).unwrap(); // keeps the old inode alive
    fs::write(tmp.path().join("new"), [2u8; 64]).unwrap();
    fs::rename(tmp.path().join("new"), &path).unwrap();
    let c = dir.lstat(OsStr::new("key")).unwrap();
    assert_ne!(a.id, c.id);
    assert_eq!(a.id, file_meta(&old).unwrap().id);
}

#[test]
fn anchored_dir_survives_renaming_its_directory() {
    let tmp = Tmp::new();
    let before = tmp.path().join("before");
    fs::create_dir(&before).unwrap();
    fs::write(before.join("entry"), [0u8; 1]).unwrap();
    let dir = AnchoredDir::open(&before).unwrap();
    let id = dir.stat_self().unwrap().id;
    assert_eq!(dir.path(), before);
    fs::rename(&before, tmp.path().join("after")).unwrap();
    assert!(fs::symlink_metadata(&before).is_err());
    let entry = dir.lstat(OsStr::new("entry")).unwrap();
    assert_eq!(entry.kind, FileKind::Regular);
    assert_eq!(dir.stat_self().unwrap().id, id);
    assert!(dir.open_read_nofollow(OsStr::new("entry")).is_ok());
}

#[test]
fn names_that_are_not_one_component_are_rejected() {
    let tmp = Tmp::new();
    let dir = AnchoredDir::open(tmp.path()).unwrap();
    for name in ["", "a/b", "/a", "a/", ".", ".."] {
        let name = OsStr::new(name);
        assert_eq!(
            dir.lstat(name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{name:?}"
        );
        assert_eq!(
            dir.open_read_nofollow(name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{name:?}"
        );
    }
}

#[test]
fn open_follows_symlinks_in_the_directory_path_but_requires_a_directory() {
    let tmp = Tmp::new();
    fs::create_dir(tmp.path().join("real")).unwrap();
    fs::write(tmp.path().join("real/f"), [0u8; 1]).unwrap();
    symlink("real", tmp.path().join("via")).unwrap();
    let dir = AnchoredDir::open(&tmp.path().join("via")).unwrap();
    assert!(dir.lstat(OsStr::new("f")).is_ok());
    assert!(AnchoredDir::open(&tmp.path().join("real/f")).is_err());
}
