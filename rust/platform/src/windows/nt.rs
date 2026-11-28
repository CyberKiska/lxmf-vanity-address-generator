//! Thin, handle-relative wrappers over `NtCreateFile` / `NtOpenFile` /
//! `NtSetInformationFile`. Every child lookup in this crate goes through
//! [`open_at`], so no path string is ever rebuilt from a directory handle.

use std::ffi::OsStr;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_INFORMATION_CLASS, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_MR_MID_NOT_FOUND, ERROR_NOT_SUPPORTED, HANDLE, NTSTATUS,
    OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// `NT_SUCCESS`: success and informational statuses are non-negative.
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Converts a failed `NTSTATUS` to an `io::Error` through the system's own
/// status-to-Win32 table, which is also what Go's `NTStatus.Errno` uses.
pub(super) fn status_error(status: NTSTATUS) -> io::Error {
    // SAFETY: RtlNtStatusToDosError takes a plain integer and returns one; it
    // touches no caller memory.
    let dos = unsafe { RtlNtStatusToDosError(status) };
    if dos == ERROR_MR_MID_NOT_FOUND {
        // The table has no entry for this status; keep the raw value visible.
        return io::Error::other(format!("NTSTATUS {:#010x}", status as u32));
    }
    match i32::try_from(dos) {
        Ok(code) => io::Error::from_raw_os_error(code),
        Err(_) => io::Error::other(format!("NTSTATUS {:#010x}", status as u32)),
    }
}

/// True for the Win32 codes that Go's `Errno.Is(errors.ErrUnsupported)` accepts
/// on Windows (`ERROR_NOT_SUPPORTED`, `ERROR_CALL_NOT_IMPLEMENTED`).
pub(super) fn is_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error().and_then(|c| u32::try_from(c).ok()),
        Some(ERROR_NOT_SUPPORTED | ERROR_CALL_NOT_IMPLEMENTED)
    )
}

/// A single path component as UTF-16, checked to fit a `UNICODE_STRING`.
pub(super) struct Component(Vec<u16>);

impl Component {
    /// Second safeguard behind `check_name` in `lib.rs`: one component, and
    /// nothing Win32 would normalise differently from NT. NT matches names
    /// literally, but Win32 strips trailing dots and spaces and treats `:` as
    /// a stream separator, so a name that differs under Win32 could be
    /// reported at one place and opened at another.
    pub(super) fn new(name: &OsStr) -> io::Result<Component> {
        let wide: Vec<u16> = name.encode_wide().collect();
        let bad = wide.is_empty()
            || wide == [u16::from(b'.')]
            || wide == [u16::from(b'.'), u16::from(b'.')]
            || wide.iter().any(|&c| {
                c == 0 || c == u16::from(b'\\') || c == u16::from(b'/') || c == u16::from(b':')
            })
            || wide
                .last()
                .is_some_and(|&c| c == u16::from(b'.') || c == u16::from(b' '));
        if bad {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "name must be a single path component",
            ));
        }
        // Length is in bytes: u16::MAX bytes is 32767 code units.
        if wide.len() > usize::from(u16::MAX) / 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }
        Ok(Component(wide))
    }

    fn byte_len(&self) -> io::Result<u16> {
        self.0
            .len()
            .checked_mul(2)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))
    }

    pub(super) fn units(&self) -> &[u16] {
        &self.0
    }
}

/// Share mode used for every child open: Go's `Openat` passes
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
pub(super) const SHARE_ALL: u32 = 1 | 2 | 4;

/// Opens or creates `name` relative to `dir`. The name is matched
/// case-insensitively, like Go (`OBJ_CASE_INSENSITIVE`). `options` must carry
/// `FILE_SYNCHRONOUS_IO_NONALERT` only together with `SYNCHRONIZE` in
/// `access`; callers pass both.
pub(super) fn open_at(
    dir: HANDLE,
    name: &Component,
    access: u32,
    attributes: u32,
    disposition: u32,
    options: u32,
) -> io::Result<OwnedHandle> {
    let bytes = name.byte_len()?;
    let object_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        // NT does not write through this pointer; `cast_mut` only satisfies
        // the struct's field type.
        Buffer: name.units().as_ptr().cast_mut(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir,
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut handle: HANDLE = null_mut();
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: `handle` and `iosb` are live locals that the call fills in.
    // `object_attributes` and the `object_name` it points to live until the
    // call returns, and `object_name.Buffer` points at `name`'s UTF-16 buffer,
    // which is `Length` bytes long (`byte_len` checked the u16 range, and the
    // length counts bytes without a terminator, as UNICODE_STRING requires).
    // The kernel copies the name during the call and keeps no pointer.
    // Allocation size, EA buffer and EA length are null/zero, which is valid.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &object_attributes,
            &mut iosb,
            null(),
            attributes,
            SHARE_ALL,
            disposition,
            options,
            null(),
            0,
        )
    };
    if !nt_success(status) {
        return Err(status_error(status));
    }
    // SAFETY: the call succeeded, so `handle` is a new, valid handle that
    // nothing else owns. OwnedHandle takes over closing it exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(super) use windows_sys::Win32::Foundation::{
    STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
};

/// Turns an `NTSTATUS` into `Ok(())` or the matching `io::Error`.
pub(super) fn check(status: NTSTATUS) -> io::Result<()> {
    if nt_success(status) {
        Ok(())
    } else {
        Err(status_error(status))
    }
}

/// `NtSetInformationFile` with a fixed-size information structure.
pub(super) fn set_info_struct<T: Copy>(
    handle: HANDLE,
    info: &T,
    class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    let Ok(length) = u32::try_from(size_of::<T>()) else {
        return STATUS_INVALID_PARAMETER;
    };
    set_info_raw(handle, std::ptr::from_ref(info).cast(), length, class)
}

/// A zeroed, 8-byte aligned buffer holding a `FILE_LINK_INFORMATION`-shaped
/// header followed by one UTF-16 name.
pub(super) struct NameInfo {
    words: Vec<u64>,
    length: u32,
}

impl NameInfo {
    #[cfg(test)]
    pub(super) fn length(&self) -> u32 {
        self.length
    }

    /// Builds the structure shared by `FILE_LINK_INFORMATION` and
    /// `FILE_RENAME_INFORMATION`: flags/ReplaceIfExists (left zero, so "do not
    /// replace"), `RootDirectory = root`, `FileNameLength` in bytes, then the
    /// name without a terminator.
    pub(super) fn new(root: HANDLE, name: &Component) -> io::Result<NameInfo> {
        use windows_sys::Wdk::Storage::FileSystem::FILE_LINK_INFORMATION as H;
        let name_offset = std::mem::offset_of!(H, FileName);
        let name_bytes = name.byte_len()?;
        // At least the whole structure: NT rejects a shorter buffer even
        // when the name itself fits (see `name_info_len`).
        let total = crate::namebuf::name_info_len(
            std::mem::size_of::<H>(),
            name_offset,
            usize::from(name_bytes),
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let length = u32::try_from(total)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let mut words = vec![0u64; total.div_ceil(8)];
        let base = words.as_mut_ptr().cast::<u8>();
        // SAFETY: `words` is zeroed and `words.len() * 8 >= total` bytes long,
        // aligned to 8; `total` is at least `size_of::<H>()` and at least
        // `name_offset + name_bytes`. Each write below stays inside `total`
        // bytes:
        // RootDirectory and FileNameLength are fields of H at their own
        // offsets (their alignment divides the offset because H is a repr(C)
        // struct and `base` is 8-aligned), and the name is written at
        // `name_offset` for exactly `name.units().len() * 2 == name_bytes`
        // bytes. Source and destination do not overlap (fresh allocation).
        unsafe {
            base.add(std::mem::offset_of!(H, RootDirectory))
                .cast::<HANDLE>()
                .write(root);
            base.add(std::mem::offset_of!(H, FileNameLength))
                .cast::<u32>()
                .write(u32::from(name_bytes));
            std::ptr::copy_nonoverlapping(
                name.units().as_ptr(),
                base.add(name_offset).cast::<u16>(),
                name.units().len(),
            );
        }
        Ok(NameInfo { words, length })
    }
}

/// `NtSetInformationFile` with a [`NameInfo`] buffer (hard link).
pub(super) fn set_info_name(
    handle: HANDLE,
    info: &NameInfo,
    class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    set_info_raw(handle, info.words.as_ptr().cast(), info.length, class)
}

fn set_info_raw(
    handle: HANDLE,
    info: *const core::ffi::c_void,
    length: u32,
    class: FILE_INFORMATION_CLASS,
) -> NTSTATUS {
    let mut iosb = IO_STATUS_BLOCK::default();
    // SAFETY: the two safe wrappers above are the only callers. `info` points
    // at `length` readable bytes owned by a reference that outlives this call
    // (a `&T` of `size_of::<T>()` bytes, or a NameInfo's 8-aligned buffer of
    // exactly `length` bytes). `handle` is borrowed from an OwnedHandle or
    // File that the caller keeps open for the call. `iosb` is a live local.
    unsafe { NtSetInformationFile(handle, &mut iosb, info, length, class) }
}
