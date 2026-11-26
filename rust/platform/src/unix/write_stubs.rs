//! Placeholders for the write-path items that only exist on Windows so far.
//! They keep the platform-neutral API in `lib.rs` compiling on Unix; the Unix
//! implementations arrive with the save-path work, which replaces this file.

use super::Dir;
use crate::FileId;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;

fn unsupported<T>() -> io::Result<T> {
    Err(io::ErrorKind::Unsupported.into())
}

impl Dir {
    pub(crate) fn open_rw_nofollow(&self, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn create_exclusive(&self, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn link_noreplace(&self, _: &OsStr, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn remove(&self, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn sync_dir(&self) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn current_path_identity(&self, _: &Path) -> io::Result<FileId> {
        unsupported()
    }
}

pub(crate) fn set_private_mode(_: &File) -> io::Result<()> {
    unsupported()
}

pub(crate) fn sync_file(_: &File) -> io::Result<()> {
    unsupported()
}
