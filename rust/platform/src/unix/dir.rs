//! Anchored directory operations on `openat`/`fstatat`; no `unsafe`.
//!
//! Basis: the example rewrite's `(dev, ino)` identity and its lstat / no-follow
//! open / identity compare read path, rebuilt on `rustix` instead of cap-std.

use crate::{FileId, FileKind, FileMeta};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, fstat, openat, statat};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

/// `(st_dev, st_ino)`. The integer widths differ between Unix systems, so both
/// are widened losslessly to `i128`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RawFileId {
    dev: i128,
    ino: i128,
}

fn wide(v: impl Into<i128>) -> i128 {
    v.into()
}

fn meta_of(st: &Stat) -> FileMeta {
    let kind = match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile => FileKind::Regular,
        FileType::Directory => FileKind::Directory,
        FileType::Symlink => FileKind::Symlink,
        _ => FileKind::Other,
    };
    FileMeta {
        kind,
        size: u64::try_from(wide(st.st_size)).unwrap_or(0),
        mode: u32::try_from(wide(st.st_mode) & 0o7777).unwrap_or(0),
        uid: Some(st.st_uid),
        id: FileId(RawFileId {
            dev: wide(st.st_dev),
            ino: wide(st.st_ino),
        }),
    }
}

pub(crate) fn file_meta(file: &File) -> io::Result<FileMeta> {
    Ok(meta_of(&fstat(file)?))
}

#[derive(Debug)]
pub(crate) struct Dir(OwnedFd);

impl Dir {
    pub(crate) fn open(path: &Path) -> io::Result<Dir> {
        // Plain `open` on the path, like os.OpenRoot: symlinks in the path
        // itself are followed, and O_DIRECTORY rejects a non-directory.
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Dir(fd))
    }

    pub(crate) fn stat_self(&self) -> io::Result<FileMeta> {
        Ok(meta_of(&fstat(&self.0)?))
    }

    pub(crate) fn lstat(&self, name: &OsStr) -> io::Result<FileMeta> {
        // statat follows symlinks unless told not to.
        Ok(meta_of(&statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)?))
    }

    pub(crate) fn open_read_nofollow(&self, name: &OsStr) -> io::Result<File> {
        // Port of safeopen_unix.go safeReadFlags: O_NONBLOCK keeps a
        // substituted FIFO from hanging the open.
        let fd = openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(File::from(fd))
    }
}
