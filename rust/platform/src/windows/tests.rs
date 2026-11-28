//! Windows-only unit tests for internals that the public API cannot reach.
//! `cargo test -p lxmf-vanity-platform --locked` runs them on Windows.

use super::Dir;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::PathBuf;

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        let dir =
            std::env::temp_dir().join(format!("lxmf-p1-05-unit-{}-{tag}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        Tmp(dir)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn remove_fallback_path_deletes_plain_and_read_only_files() {
    // `posix = false` is the path taken on FAT and old Windows 10 builds.
    let tmp = Tmp::new("fallback");
    let dir = Dir::open(&tmp.0).unwrap();
    for (file, readonly) in [("plain", false), ("ro", true)] {
        let path = tmp.0.join(file);
        fs::write(&path, b"x").unwrap();
        if readonly {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_readonly(true);
            fs::set_permissions(&path, perms).unwrap();
        }
        dir.remove_with(OsStr::new(file), false).unwrap();
        assert!(!path.exists(), "{file} still exists");
    }
    let err = dir.remove_with(OsStr::new("plain"), false).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn remove_fallback_leaves_an_open_file_delete_pending_until_closed() {
    let tmp = Tmp::new("pending");
    let dir = Dir::open(&tmp.0).unwrap();
    let path = tmp.0.join("held");
    let held = fs::File::create(&path).unwrap();
    // Our handle shares delete (std's default), so the entry can be removed.
    dir.remove_with(OsStr::new("held"), false).unwrap();
    drop(held);
    assert!(!path.exists());
}

#[test]
fn an_unsupported_link_error_is_recognised() {
    let err = io::Error::from_raw_os_error(50); // ERROR_NOT_SUPPORTED
    assert!(super::nt::is_unsupported(&err));
    let err = io::Error::from_raw_os_error(183); // ERROR_ALREADY_EXISTS
    assert!(!super::nt::is_unsupported(&err));
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
}

#[test]
fn status_errors_map_through_the_system_table() {
    use windows_sys::Win32::Foundation::{
        STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    };
    assert_eq!(
        super::nt::status_error(STATUS_OBJECT_NAME_COLLISION).kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        super::nt::status_error(STATUS_OBJECT_NAME_NOT_FOUND).kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn name_info_buffer_covers_the_structure_for_short_and_long_names() {
    use super::nt::{Component, NameInfo};
    use windows_sys::Wdk::Storage::FileSystem::FILE_LINK_INFORMATION;
    let min = std::mem::size_of::<FILE_LINK_INFORMATION>();
    let offset = std::mem::offset_of!(FILE_LINK_INFORMATION, FileName);
    for text in ["a", "ab", "abcdefghij", &"x".repeat(255)] {
        let name = Component::new(OsStr::new(text)).unwrap();
        let info = NameInfo::new(std::ptr::null_mut(), &name).unwrap();
        let length = usize::try_from(info.length()).unwrap();
        assert!(length >= min, "{} bytes for {text:?}", info.length());
        assert!(length >= offset + 2 * text.len());
    }
}
