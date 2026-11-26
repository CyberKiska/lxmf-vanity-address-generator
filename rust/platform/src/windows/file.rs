//! Operations on an open file, and the process-level items.

use crate::HardenError;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO, FILE_TYPE_CHAR, FileBasicInfo,
    GetFileType, SetFileInformationByHandle,
};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};

/// Go's `File.Chmod(0600)` on Windows: clears `FILE_ATTRIBUTE_READONLY` and
/// changes nothing else (Port of `poll.FD.Fchmod`). Needs a handle with
/// `FILE_WRITE_ATTRIBUTES`, which `create_exclusive` provides.
pub(crate) fn set_private_mode(file: &File) -> io::Result<()> {
    let handle = file.as_raw_handle();
    let info = super::meta::by_handle(handle)?;
    let attrs = info.dwFileAttributes & !FILE_ATTRIBUTE_READONLY;
    if attrs == info.dwFileAttributes {
        return Ok(());
    }
    let basic = FILE_BASIC_INFO {
        // Zero times mean "leave unchanged". A zero attribute set would also
        // mean "unchanged", so a file whose only attribute was READONLY gets
        // NORMAL instead.
        FileAttributes: if attrs == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            attrs
        },
        ..FILE_BASIC_INFO::default()
    };
    let size = u32::try_from(size_of::<FILE_BASIC_INFO>()).map_err(io::Error::other)?;
    // SAFETY: `file` owns a live handle for the call. `basic` is a live
    // FILE_BASIC_INFO and `size` is its exact size, as the FileBasicInfo
    // class requires. The call only reads the buffer.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            std::ptr::from_ref(&basic).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `FlushFileBuffers`, which is what `File::sync_all` calls on Windows.
pub(crate) fn sync_file(file: &File) -> io::Result<()> {
    file.sync_all()
}

/// Go's `ModeCharDevice` check on standard error: `GetFileType == FILE_TYPE_CHAR`
/// (a console or `NUL`, not a pipe or a file).
pub(crate) fn stderr_is_char_device() -> bool {
    // SAFETY: GetStdHandle takes a constant and returns a handle value that the
    // process owns; nothing is dereferenced or closed here.
    let handle = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return false;
    }
    // SAFETY: `handle` is the process's standard-error handle checked above.
    // GetFileType only queries it; a stale value yields FILE_TYPE_UNKNOWN.
    unsafe { GetFileType(handle) == FILE_TYPE_CHAR }
}

// Go's harden_other.go is `func hardenProcess() error { return nil }`:
// nothing to do on Windows, and no "hardening unavailable" notice.
pub(crate) fn harden_process() -> Result<(), HardenError> {
    Ok(())
}

pub(crate) fn effective_uid() -> Option<u32> {
    None
}
