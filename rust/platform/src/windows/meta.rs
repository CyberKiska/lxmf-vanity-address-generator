//! Metadata and identity read from an open handle.

use crate::{FileId, FileKind, FileMeta};
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_TYPE_DISK, FileAttributeTagInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFileType,
};

// `winnt.h` reparse tags. Windows' `IsReparseTagNameSurrogate` is bit 29.
const TAG_NAME_SURROGATE: u32 = 0x2000_0000;
const TAG_DEDUP: u32 = 0x8000_0013;

/// `(volume serial, 64-bit file index)` from `GetFileInformationByHandle`:
/// Go's `os.SameFile` semantics. ReFS can need the 128-bit `FILE_ID_INFO`;
/// Go has the same limit (see WINDOWS.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RawFileId {
    volume: u32,
    index: u64,
}

pub(super) fn by_handle(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is borrowed from a live handle by the caller, and
    // `info` is a live, writable BY_HANDLE_FILE_INFORMATION that the call
    // fills in.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// The reparse tag of a handle opened with `FILE_OPEN_REPARSE_POINT`.
pub(super) fn reparse_tag(handle: HANDLE) -> io::Result<u32> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    let size = u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).map_err(io::Error::other)?;
    // SAFETY: `handle` is borrowed from a live handle by the caller. The
    // buffer is a live FILE_ATTRIBUTE_TAG_INFO and `size` is its exact size,
    // as the FileAttributeTagInfo class requires.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut info).cast(),
            size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.ReparseTag)
}

pub(super) fn is_reparse(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// True when the handle names a symlink or a junction (any name-surrogate
/// reparse point).
pub(super) fn is_name_surrogate(handle: HANDLE) -> io::Result<bool> {
    let info = by_handle(handle)?;
    if !is_reparse(&info) {
        return Ok(false);
    }
    Ok(reparse_tag(handle)? & TAG_NAME_SURROGATE != 0)
}

/// Metadata of an open handle. The kind follows Go's `fileStat.Mode`:
/// name-surrogate reparse points (symlink, junction) are reported as
/// `Symlink` (the task decision; Go calls a junction irregular, and both are
/// "not regular" to every caller), dedup files and directories with another
/// reparse tag count as their underlying type, other reparse points are
/// `Other`.
pub(super) fn handle_meta(handle: HANDLE) -> io::Result<FileMeta> {
    let info = by_handle(handle)?;
    let kind = if is_reparse(&info) {
        let tag = reparse_tag(handle)?;
        if tag & TAG_NAME_SURROGATE != 0 {
            FileKind::Symlink
        } else if tag == TAG_DEDUP || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            // Go: dedup files count as regular, and a directory with another
            // reparse tag (cloud sync folders) is still a directory (Go also
            // marks it irregular, which no caller of `kind` looks at).
            plain_kind(&info)
        } else {
            FileKind::Other
        }
    } else {
        plain_kind(&info)
    };
    Ok(FileMeta {
        kind,
        size: u64::from(info.nFileSizeHigh) << 32 | u64::from(info.nFileSizeLow),
        mode: 0,
        uid: None,
        id: id_of(&info),
    })
}

fn plain_kind(info: &BY_HANDLE_FILE_INFORMATION) -> FileKind {
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        FileKind::Directory
    } else {
        FileKind::Regular
    }
}

pub(super) fn id_of(info: &BY_HANDLE_FILE_INFORMATION) -> FileId {
    FileId(RawFileId {
        volume: info.dwVolumeSerialNumber,
        index: u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
    })
}

pub(crate) fn file_meta(file: &File) -> io::Result<FileMeta> {
    let handle = file.as_raw_handle();
    // SAFETY: `file` owns a live handle for the duration of the call.
    let file_type = unsafe { GetFileType(handle) };
    let mut meta = handle_meta(handle)?;
    if file_type != FILE_TYPE_DISK {
        // Console, pipe or unknown: never a regular file or directory.
        meta.kind = FileKind::Other;
    }
    Ok(meta)
}
