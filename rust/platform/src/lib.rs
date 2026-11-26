//! Operating-system adapters for lxmf-vanity.
//!
//! This file is the platform-neutral API. The Unix implementation lives in
//! `unix/`, the Windows one in `windows/`; each provides the `imp` items used
//! below, so both platforms share the validation and the documented contract.
//!
//! Unsafe code is denied here. Only `windows/` may opt in, with a written
//! justification for each use.
#![deny(unsafe_code)]

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as imp;

#[cfg(windows)]
mod windows;
// Placeholder until the Windows layer lands: it must replace this module with
// `use windows as imp;` and provide the same items (`Dir`, `RawFileId`,
// `file_meta`, `harden_process`, `stderr_is_char_device`, `effective_uid`).
#[cfg(windows)]
mod imp {
    use super::{FileMeta, HardenError};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    fn unsupported<T>() -> io::Result<T> {
        Err(io::ErrorKind::Unsupported.into())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct RawFileId;

    #[derive(Debug)]
    pub(crate) struct Dir;

    impl Dir {
        pub(crate) fn open(_: &Path) -> io::Result<Dir> {
            unsupported()
        }
        pub(crate) fn stat_self(&self) -> io::Result<FileMeta> {
            unsupported()
        }
        pub(crate) fn lstat(&self, _: &OsStr) -> io::Result<FileMeta> {
            unsupported()
        }
        pub(crate) fn open_read_nofollow(&self, _: &OsStr) -> io::Result<File> {
            unsupported()
        }
    }

    pub(crate) fn file_meta(_: &File) -> io::Result<FileMeta> {
        unsupported()
    }
    // Go's harden_other.go is `func hardenProcess() error { return nil }`:
    // nothing to do on Windows, and no "hardening unavailable" notice.
    pub(crate) fn harden_process() -> Result<(), HardenError> {
        Ok(())
    }
    pub(crate) fn stderr_is_char_device() -> bool {
        false
    }
    pub(crate) fn effective_uid() -> Option<u32> {
        None
    }
}

/// What a directory entry or open file is. `Other` covers FIFOs, devices,
/// sockets and anything else that is not one of the first three.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// Identity of a file on disk, with the semantics of Go's `os.SameFile`:
/// two values are equal when they name the same file. On Unix this is the
/// `(st_dev, st_ino)` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId(pub(crate) imp::RawFileId);

/// Metadata read without following a final symlink (`lstat`) or from an open
/// handle (`fstat`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMeta {
    pub kind: FileKind,
    pub size: u64,
    /// Unix permission bits including set-id and sticky (`st_mode & 0o7777`).
    /// Zero where the platform has no such bits.
    pub mode: u32,
    /// Owner user id; `None` where the platform has none.
    pub uid: Option<u32>,
    pub id: FileId,
}

/// A directory opened once and then used for every later lookup, so that
/// renaming or replacing the directory's path cannot redirect an operation
/// (the equivalent of Go's `os.Root`).
///
/// `name` arguments must be a single path component; an empty name, a name
/// with a path separator, `.` and `..` are rejected with `InvalidInput`. The
/// caller validates names too; this is a second safeguard.
#[derive(Debug)]
pub struct AnchoredDir {
    inner: imp::Dir,
    path: std::path::PathBuf,
}

impl AnchoredDir {
    /// Opens `path` as a directory. Symlinks in `path` itself are followed,
    /// like `os.OpenRoot`. The caller passes an already cleaned absolute path.
    pub fn open(path: &Path) -> io::Result<AnchoredDir> {
        Ok(AnchoredDir {
            inner: imp::Dir::open(path)?,
            path: path.to_path_buf(),
        })
    }

    /// The path given to [`AnchoredDir::open`], for messages only. It is not
    /// used for any later operation.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Metadata of the directory itself, from its handle.
    pub fn stat_self(&self) -> io::Result<FileMeta> {
        self.inner.stat_self()
    }

    /// Metadata of entry `name`, not following a symlink (`fstatat` with
    /// `AT_SYMLINK_NOFOLLOW`).
    pub fn lstat(&self, name: &OsStr) -> io::Result<FileMeta> {
        check_name(name)?;
        self.inner.lstat(name)
    }

    /// Opens entry `name` read-only without following a symlink and without
    /// blocking on a FIFO (`O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`).
    /// The caller must check the kind with [`file_meta`] on the result: the
    /// open itself accepts any non-symlink entry.
    pub fn open_read_nofollow(&self, name: &OsStr) -> io::Result<File> {
        check_name(name)?;
        self.inner.open_read_nofollow(name)
    }
}

/// The second safeguard before any `os.Root`-style call: one component only.
fn check_name(name: &OsStr) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || contains_separator(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name must be a single path component",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn contains_separator(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().contains(&b'/')
}

#[cfg(windows)]
fn contains_separator(name: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide()
        .any(|c| c == u16::from(b'/') || c == u16::from(b'\\'))
}

/// Metadata of an open file (`fstat`).
pub fn file_meta(file: &File) -> io::Result<FileMeta> {
    imp::file_meta(file)
}

/// Every error [`harden_process`] met. Hardening is best effort: the caller
/// prints `Notice: best-effort process hardening unavailable: <error>` and
/// continues. Several errors are joined with newlines, like Go's
/// `errors.Join`.
#[derive(Debug)]
pub struct HardenError(Vec<io::Error>);

impl HardenError {
    // Unix only for now: the Windows hardening never fails (as in Go), so the
    // Windows layer can drop this cfg if it ever collects errors.
    #[cfg(unix)]
    pub(crate) fn new(errors: Vec<io::Error>) -> HardenError {
        HardenError(errors)
    }
}

impl fmt::Display for HardenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, err) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for HardenError {}

/// Best-effort process hardening: lowers the soft core-file limit to 0 (the
/// hard limit is kept) and, on Linux, clears the dumpable flag. Every step is
/// tried even when an earlier one failed. Call it from `main` only, never in
/// a test process (use the `harden_probe` helper binary).
pub fn harden_process() -> Result<(), HardenError> {
    imp::harden_process()
}

/// True when standard error is a character device, like Go's
/// `ModeCharDevice` check. This is not `IsTerminal`: `/dev/null` counts. On
/// Windows it is the console check.
pub fn stderr_is_char_device() -> bool {
    imp::stderr_is_char_device()
}

/// The effective user id; `None` on Windows.
pub fn effective_uid() -> Option<u32> {
    imp::effective_uid()
}
