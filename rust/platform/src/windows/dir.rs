//! Anchored directory operations on NT handle-relative calls.
//!
//! Go reference (read, not copied): `os.Root` on Windows
//! (`root_windows.go`, `internal/syscall/windows/at_windows.go`). Every child
//! operation names a single component relative to the open directory handle.

use super::meta::{by_handle, handle_meta, id_of, is_name_surrogate};
use super::nt::{
    Component, NameInfo, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    check, is_unsupported, open_at, set_info_name, set_info_struct, status_error,
};
use crate::{FileId, FileMeta};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DISPOSITION_DELETE, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_INFORMATION, FILE_DISPOSITION_INFORMATION_EX,
    FILE_DISPOSITION_POSIX_SEMANTICS, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    FileDispositionInformation, FileDispositionInformationEx, FileLinkInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_CANT_ACCESS_FILE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
    FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FileBasicInfo, ReOpenFile, SYNCHRONIZE, SetFileInformationByHandle,
};

const FILE_READ_EA: u32 = 0x0008;
const SHARE_ALL: u32 = super::nt::SHARE_ALL;

/// Options shared by every child open: Go's `Openat` adds
/// `FILE_OPEN_FOR_BACKUP_INTENT` and synchronous I/O, and always opens the
/// entry itself when it is a reparse point (`FILE_OPEN_REPARSE_POINT`).
const CHILD_OPTIONS: u32 =
    FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT;

/// The directory handle. It is opened like Go's `os.OpenRoot`
/// (`syscall.Open`): read access, `FILE_SHARE_READ | FILE_SHARE_WRITE` and no
/// `FILE_SHARE_DELETE`, so while it is open the directory cannot be renamed or
/// deleted. See WINDOWS.md, "Share modes".
#[derive(Debug)]
pub(crate) struct Dir(OwnedHandle);

impl Dir {
    pub(crate) fn open(path: &Path) -> io::Result<Dir> {
        // The one path-based open, like os.OpenRoot: symlinks in the path
        // itself are followed. std adds the extended-length prefix for long
        // paths. BACKUP_SEMANTICS is what lets CreateFile open a directory.
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let handle = OwnedHandle::from(file);
        let info = by_handle(handle.as_raw_handle())?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "not a directory",
            ));
        }
        Ok(Dir(handle))
    }

    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0.as_raw_handle()
    }

    pub(crate) fn stat_self(&self) -> io::Result<FileMeta> {
        handle_meta(self.raw())
    }

    pub(crate) fn lstat(&self, name: &OsStr) -> io::Result<FileMeta> {
        let name = Component::new(name)?;
        // Attribute-only access never conflicts with another handle's share
        // mode, so a file that is open elsewhere can still be inspected.
        let handle = open_at(
            self.raw(),
            &name,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_ATTRIBUTE_NORMAL,
            FILE_OPEN,
            CHILD_OPTIONS,
        )?;
        handle_meta(handle.as_raw_handle())
    }

    /// Opens `name` and refuses a symlink or junction, like `O_NOFOLLOW`. The
    /// entry is opened with `FILE_OPEN_REPARSE_POINT`, so a link is opened as
    /// itself and never followed; the check is on the handle, so the name
    /// cannot be swapped between check and use.
    fn open_checked(&self, name: &OsStr, access: u32, extra: u32) -> io::Result<File> {
        let name = Component::new(name)?;
        let handle = open_at(
            self.raw(),
            &name,
            access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            FILE_ATTRIBUTE_NORMAL,
            FILE_OPEN,
            CHILD_OPTIONS | extra,
        )?;
        if is_name_surrogate(handle.as_raw_handle())? {
            // What OBJ_DONT_REPARSE would report (ELOOP in Go).
            return Err(io::Error::from_raw_os_error(ERROR_CANT_ACCESS_FILE as i32));
        }
        Ok(File::from(handle))
    }

    pub(crate) fn open_read_nofollow(&self, name: &OsStr) -> io::Result<File> {
        self.open_checked(name, FILE_GENERIC_READ, 0)
    }

    pub(crate) fn open_rw_nofollow(&self, name: &OsStr) -> io::Result<File> {
        self.open_checked(
            name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_NON_DIRECTORY_FILE,
        )
    }

    pub(crate) fn create_exclusive(&self, name: &OsStr) -> io::Result<File> {
        let component = Component::new(name)?;
        // FILE_CREATE fails with STATUS_OBJECT_NAME_COLLISION when the name
        // exists in any form. FILE_OPEN_REPARSE_POINT makes a dangling or
        // valid link count as "exists" instead of being followed.
        let created = open_at(
            self.raw(),
            &component,
            FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
            FILE_ATTRIBUTE_NORMAL,
            FILE_CREATE,
            CHILD_OPTIONS | FILE_NON_DIRECTORY_FILE,
        );
        match created {
            Ok(handle) => Ok(File::from(handle)),
            // Observed on native CI: creating a file over an existing
            // directory or junction fails with access denied, not a collision
            // (NT reports the directory before the collision). Access denied
            // is also what a real permission problem looks like, so confirm
            // with a no-follow lookup: if the name exists, it exists. A name
            // that is absent keeps the original error.
            Err(err) if err.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok() => {
                if self.lstat(name).is_ok() {
                    Err(io::Error::new(io::ErrorKind::AlreadyExists, err))
                } else {
                    Err(err)
                }
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn link_noreplace(&self, existing: &OsStr, new: &OsStr) -> io::Result<()> {
        let existing = Component::new(existing)?;
        let new = Component::new(new)?;
        // Port of at_windows.go Linkat: the source is opened relative to the
        // directory, without following, with FILE_WRITE_ATTRIBUTES.
        let source = open_at(
            self.raw(),
            &existing,
            SYNCHRONIZE | FILE_WRITE_ATTRIBUTES,
            FILE_ATTRIBUTE_NORMAL,
            FILE_OPEN,
            CHILD_OPTIONS,
        )?;
        // The header's flags field is zero: ReplaceIfExists = FALSE. The
        // target name is relative to the same directory handle.
        let info = NameInfo::new(self.raw(), &new)?;
        let status = set_info_name(source.as_raw_handle(), &info, FileLinkInformation);
        check(status).map_err(|err| {
            if is_unsupported(&err) {
                io::Error::new(io::ErrorKind::Unsupported, err)
            } else {
                err
            }
        })
    }

    pub(crate) fn remove(&self, name: &OsStr) -> io::Result<()> {
        self.remove_with(name, true)
    }

    /// `posix` false forces the pre-Windows-10-1607 / FAT path, so tests can
    /// run it on any filesystem.
    pub(super) fn remove_with(&self, name: &OsStr, posix: bool) -> io::Result<()> {
        let name = Component::new(name)?;
        // Port of at_windows.go Deleteat: open the entry itself (never a
        // reparse target) with DELETE, retrying with DELETE alone when the
        // entry's own ACL denies attribute reads but the parent allows delete.
        let open = |access| {
            open_at(
                self.raw(),
                &name,
                access,
                FILE_ATTRIBUTE_NORMAL,
                FILE_OPEN,
                FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
            )
        };
        let handle = match open(FILE_READ_ATTRIBUTES | DELETE) {
            Err(err) if err.raw_os_error() == i32::try_from(ERROR_ACCESS_DENIED).ok() => {
                open(DELETE)?
            }
            other => other?,
        };
        if posix {
            let info = FILE_DISPOSITION_INFORMATION_EX {
                Flags: FILE_DISPOSITION_DELETE
                    | FILE_DISPOSITION_POSIX_SEMANTICS
                    // Like os.Remove on Unix, read-only files can be removed.
                    | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
            };
            let status =
                set_info_struct(handle.as_raw_handle(), &info, FileDispositionInformationEx);
            match status {
                s if s >= 0 => return Ok(()),
                STATUS_INVALID_INFO_CLASS | STATUS_INVALID_PARAMETER | STATUS_NOT_SUPPORTED => {}
                s => return Err(status_error(s)),
            }
        }
        remove_fallback(&handle)
    }

    pub(crate) fn sync_dir(&self) -> io::Result<()> {
        // Go opens directories read-only and FlushFileBuffers needs a writable
        // handle, so Go reports "directory sync unsupported" on Windows.
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(crate) fn current_path_identity(&self, path: &Path) -> io::Result<FileId> {
        // Port of output.go checkLocation: reopen "<path>\." by path. This is
        // the only path-based use after open, and its purpose is to compare the
        // path with the handle. Attribute-only access with full sharing never
        // conflicts with our handle.
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path.join("."))?;
        Ok(id_of(&by_handle(file.as_raw_handle())?))
    }
}

/// Port of at_windows.go deleteatFallback: clear READONLY through a second
/// handle derived from `handle` (not from the name), then set the plain
/// disposition. The name goes away when the last handle closes.
fn remove_fallback(handle: &OwnedHandle) -> io::Result<()> {
    let raw = handle.as_raw_handle();
    let info = by_handle(raw)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_READONLY != 0 {
        // SAFETY: `raw` is a live handle owned by `handle`. ReOpenFile has no
        // pointer arguments; it returns a new handle or INVALID_HANDLE_VALUE.
        let reopened = unsafe {
            ReOpenFile(
                raw,
                FILE_WRITE_ATTRIBUTES,
                SHARE_ALL,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            )
        };
        if reopened == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `reopened` is a new valid handle that nothing else owns, so
        // OwnedHandle closes it exactly once (also on the error path below).
        let reopened = unsafe { OwnedHandle::from_raw_handle(reopened) };
        let attrs = info.dwFileAttributes & !FILE_ATTRIBUTE_READONLY;
        let basic = FILE_BASIC_INFO {
            FileAttributes: if attrs == 0 {
                FILE_ATTRIBUTE_NORMAL
            } else {
                attrs
            },
            ..FILE_BASIC_INFO::default()
        };
        let size = u32::try_from(size_of::<FILE_BASIC_INFO>()).map_err(io::Error::other)?;
        // SAFETY: `reopened` is live. `basic` is a live FILE_BASIC_INFO and
        // `size` is its exact size, as the FileBasicInfo class requires.
        let ok = unsafe {
            SetFileInformationByHandle(
                reopened.as_raw_handle(),
                FileBasicInfo,
                std::ptr::from_ref(&basic).cast(),
                size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    check(set_info_struct(
        raw,
        &disposition,
        FileDispositionInformation,
    ))
}
