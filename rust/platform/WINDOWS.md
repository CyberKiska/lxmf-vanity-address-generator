# Windows adapter: qualification of the file primitives

Status: **implemented and compile-checked, awaiting owner verification.** Nothing here has run on Windows yet. The native results are filled in the "Evidence" table when the owner-run CI has passed on both x64 and arm64.

## Decision this document supports

The adapter must do directory-relative, no-follow, no-replace operations and file identity without ever rebuilding a path from the directory handle, because a rebuilt path reintroduces the race the anchored directory exists to prevent. The design answer is: **yes, every primitive can be made handle-relative on Windows.** All of them are `NtCreateFile`, `NtSetInformationFile` and `GetFileInformationByHandle` calls on handles; the only two path-based opens are the initial `AnchoredDir::open` (as in Go's `os.OpenRoot`) and `current_path_identity` (whose purpose is to compare the path with the handle).

## Running the native tests

On a Windows machine, from the repository root:

```text
cd rust && cargo test -p lxmf-vanity-platform --locked
```

This runs the library unit tests (`src/windows/tests.rs`), `tests/windows_fs.rs` and `tests/windows_stderr.rs`. The same tests also run in the existing `Rust checks (windows-latest)` (x64) and `Rust checks (windows-11-arm)` (arm64) jobs of `.github/workflows/rust.yml`, through `cargo test --workspace --locked`.

Creating symlinks needs Administrator rights or Developer Mode. Hosted runners are administrators. A machine without the privilege fails the symlink tests unless `LXMF_ALLOW_SKIP_SYMLINKS=1` is set; skipped tests print `SKIPPED (not a pass)` and are never evidence.

## Primitives

All child operations open `name` with `NtCreateFile` and `OBJECT_ATTRIBUTES { RootDirectory = <dir handle>, ObjectName = <one UTF-16 component>, Attributes = OBJ_CASE_INSENSITIVE }`, with `FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT` and share mode `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`. These are Go's flags (`Openat` in `at_windows.go`): Go matches names case-insensitively unless a POSIX-semantics flag is passed, and shares everything on child opens.

| Primitive | Calls and flags | Compared with Go `os.Root` | Unix implementation (P1-04, P3-01) |
|---|---|---|---|
| `AnchoredDir::open` | std `OpenOptions`: `GENERIC_READ`, share `READ \| WRITE`, `FILE_FLAG_BACKUP_SEMANTICS` (which is `CreateFileW`); then `GetFileInformationByHandle` to require a directory | Same flags as `syscall.Open` in `openRootNolog`: no `FILE_SHARE_DELETE` (see "Share modes") | `open(O_RDONLY \| O_DIRECTORY)` |
| `stat_self` | `GetFileInformationByHandle` on the handle | `Root.Stat(".")` | `fstat` |
| `lstat` | child open with access `FILE_READ_ATTRIBUTES \| SYNCHRONIZE`, `FILE_OPEN_REPARSE_POINT`; then `GetFileInformationByHandle`, and `GetFileInformationByHandleEx(FileAttributeTagInfo)` only for a reparse point | `rootStat` with `O_FILE_FLAG_OPEN_REPARSE_POINT`. Attribute-only access never conflicts with another handle's share mode | `fstatat(AT_SYMLINK_NOFOLLOW)` |
| `open_read_nofollow` | child open, `FILE_GENERIC_READ`, `FILE_OPEN_REPARSE_POINT`; then reject a name-surrogate reparse point from the handle (`ERROR_CANT_ACCESS_FILE`, 1920) | Go uses `OBJ_DONT_REPARSE` and returns `ELOOP`; this design needs no `OBJ_DONT_REPARSE` (not supported by Windows 10 build 10240, the reason for Go's `openatFallback`) and the check is on the handle, so the name cannot change between check and use | `openat(O_NOFOLLOW)`: ELOOP |
| `open_rw_nofollow` | as above with `FILE_GENERIC_READ \| FILE_GENERIC_WRITE` and `FILE_NON_DIRECTORY_FILE` | `O_RDWR` open | `openat(O_RDWR \| O_NOFOLLOW)` |
| `create_exclusive` | `FILE_CREATE`, access `FILE_GENERIC_WRITE \| FILE_READ_ATTRIBUTES \| FILE_READ_EA`, `FILE_NON_DIRECTORY_FILE`, `FILE_OPEN_REPARSE_POINT`, attributes `FILE_ATTRIBUTE_NORMAL`. `STATUS_OBJECT_NAME_COLLISION` becomes `AlreadyExists` | `O_CREAT \| O_EXCL` in `Openat` (`FILE_CREATE` plus `FILE_OPEN_REPARSE_POINT`, so a dangling link counts as existing) | `openat(O_CREAT \| O_EXCL \| O_NOFOLLOW)` |
| `link_noreplace` | open the source relative to the directory (`SYNCHRONIZE \| FILE_WRITE_ATTRIBUTES`, `FILE_OPEN_REPARSE_POINT`); `NtSetInformationFile(FileLinkInformation)` with `ReplaceIfExists = FALSE` and `RootDirectory` = the directory handle | `Linkat` in `at_windows.go`, same calls | `linkat` |
| `remove` | open the entry itself with `FILE_READ_ATTRIBUTES \| DELETE` (retry with `DELETE` alone on access denied), `FILE_OPEN_REPARSE_POINT`; delete through that handle with `FileDispositionInformationEx` = `DELETE \| POSIX_SEMANTICS \| IGNORE_READONLY_ATTRIBUTE`; on `STATUS_INVALID_INFO_CLASS`, `STATUS_INVALID_PARAMETER` or `STATUS_NOT_SUPPORTED`, clear `READONLY` through `ReOpenFile` of the same handle and use `FileDispositionInformation` | `Deleteat` in `at_windows.go`, same sequence | `unlinkat` |
| `sync_dir` | none: `Err(Unsupported)` | `syncDirectory` returns `errDirSyncUnsupported` on Windows (Go opens directories read-only and `FlushFileBuffers` needs a writable handle) | `fsync` on the directory |
| `current_path_identity` | std `OpenOptions` on `<path>\.`: access `FILE_READ_ATTRIBUTES`, share all, `FILE_FLAG_BACKUP_SEMANTICS`; identity from `GetFileInformationByHandle` | `checkLocation`; attribute-only access with full sharing avoids the "reopens the directory with no sharing rights" problem its comment mentions | `open(path + "/.")` |
| `file_meta` | `GetFileType`, `GetFileInformationByHandle`, `FileAttributeTagInfo` for reparse points. Anything but `FILE_TYPE_DISK` is `Other` | `fileStat` / `Mode` | `fstat` |
| `set_private_mode` | `GetFileInformationByHandle` then `SetFileInformationByHandle(FileBasicInfo)` clearing only `FILE_ATTRIBUTE_READONLY` (zero times, so nothing else changes; `FILE_ATTRIBUTE_NORMAL` if no other attribute remains, because a zero attribute set means "unchanged") | `Fchmod(0600)` in `internal/poll`. Go would write `0` and leave a file whose only attribute was READONLY unchanged | `fchmod(0600)` |
| `sync_file` | `File::sync_all` (`FlushFileBuffers`) | `File.Sync` | `fsync` / `F_FULLFSYNC` |
| `stderr_is_char_device` | `GetStdHandle(STD_ERROR_HANDLE)`, `GetFileType == FILE_TYPE_CHAR` (console or `NUL`) | `ModeCharDevice` from `fileStat` | `S_ISCHR` |
| `harden_process`, `effective_uid` | `Ok(())`, `None` | `harden_other.go` does nothing | rlimit, `prctl`, `geteuid` |

### Names

`lib.rs` rejects empty names, `.`, `..` and `\` or `/`. The Windows layer also rejects `:` (stream syntax), NUL, and a trailing `.` or space. NT matches names literally, but Win32 strips trailing dots and spaces and reads `:` as a stream separator, so a name accepted here could be shown at one path and opened at another. P1-09's `IsLocal` port must reject the same names first. Wildcards (`*`, `?`, `<`, `>`, `"`) are left to NT, which refuses them in an open or create. Short (8.3) aliases are not handled: creating `ABCDEF~1.TXT` while a long name owns that alias reports a collision.

### Case

Child names are matched case-insensitively, like Go. On a directory marked case-sensitive (per-directory flag, WSL) NTFS ignores `OBJ_CASE_INSENSITIVE`, and two names that differ only in case are distinct. Go behaves the same.

### Share modes

- **Directory handle:** `FILE_SHARE_READ | FILE_SHARE_WRITE`, no `FILE_SHARE_DELETE`, exactly as Go's `OpenRoot` (`syscall.Open`). While it is open the directory **cannot be renamed or deleted**.
- **Task text versus Go.** The task says Go allows renaming the opened directory and then reports it as moved. Go's source says otherwise: `syscall.Open` uses `sharemode := FILE_SHARE_READ | FILE_SHARE_WRITE`, and Go's own test `TestOutputDirectoryReplacementCannotRedirectIdentity` is skipped on Windows with "open directory handles may prohibit renaming on Windows". I followed Go. This is reported as an open question, and `an_open_directory_cannot_be_renamed_like_in_go` pins it. Changing it later means adding `FILE_SHARE_DELETE` to `Dir::open` and flipping that one test.
- **Consequence for "moved directory".** A rename is refused, so the real-world "path replaced" case on Windows is a junction or symlink in the requested path being retargeted. `replaced_path_is_detected_and_operations_stay_in_the_opened_directory` covers it: `current_path_identity` differs from `stat_self().id`, and operations keep landing in the opened directory.
- **Child files:** all of read, write and delete are shared (Go's flags). That is what lets `remove` delete a file this process still holds open.
- **Created files:** no sharing beyond what Go uses.

### Identity

`FileId` is `(dwVolumeSerialNumber, nFileIndexHigh << 32 | nFileIndexLow)`, Go's `os.SameFile` semantics (`fileStat.loadFileId`). **Option for an owner decision:** `FILE_ID_INFO` (128-bit, `GetFileInformationByHandleEx(FileIdInfo)`) would avoid index collisions on ReFS, where the 64-bit index is not guaranteed unique. Go has the same limitation. Parity was kept, and FAT/exFAT have no 128-bit identifiers. The basis rewrite used `FILE_ID_INFO`.

### Errors

An `NTSTATUS` is converted with `RtlNtStatusToDosError`, the table Go's `NTStatus.Errno` uses, and then to `io::Error::from_raw_os_error`. `link_noreplace` returns `ErrorKind::Unsupported` for exactly the Win32 codes Go's `Errno.Is(ErrUnsupported)` accepts (`ERROR_NOT_SUPPORTED` 50, `ERROR_CALL_NOT_IMPLEMENTED` 120). **Unverified:** a hard link on FAT may fail with `STATUS_INVALID_DEVICE_REQUEST`, which the table maps to `ERROR_INVALID_FUNCTION` (1), outside that set. Go would treat it as a plain link error, and so does this layer. If FAT should fall back to exclusive create, P3-02 or the owner has to decide; it was not changed here, to keep Go's behavior.

A link may exist despite an error return (the Go code re-checks with `Lstat` and `SameFile`). This layer never hides such a case: it returns the error as is, and the caller re-checks identity.

### Delete semantics

With POSIX semantics (Windows 10 1607 or later, NTFS) the name disappears at once, even while other handles are open. Without them (FAT, older builds) the entry stays *delete pending* until the last handle closes. The fallback is exercised by a unit test through `Dir::remove_with(name, false)`.

## Race analysis

Each primitive names a single component relative to a handle that the process owns, so none of them resolves any path component again.

| Step | What an attacker who can change the directory could try | Why it fails or is detected |
|---|---|---|
| Any child open | Replace `name` by a symlink or junction between a check and the open | The open itself uses `FILE_OPEN_REPARSE_POINT` and never follows. `open_*_nofollow` check the **handle** it returned, not the name |
| `create_exclusive` | Plant a dangling symlink, hard link or directory at the name | `FILE_CREATE` fails with a collision for any existing entry, links included |
| `link_noreplace` | Replace the source name after the open, or the target after the call | The source is held as a handle; the link is created from that handle. The target name is created atomically with `ReplaceIfExists = FALSE`. Replacing the *source* name leaves a link to the file that was opened, which is what the caller compares by identity |
| `remove` | Swap the name between check and delete | The entry is opened first and deleted through that handle. A different file under the name is not touched. The caller still compares identity before calling `remove` |
| Directory path replaced after open | Rename the directory (blocked by the share mode), retarget a junction in the path, or replace a parent | The handle keeps its directory. `current_path_identity` re-resolves the path and the caller compares it with `stat_self().id` |
| Initial open | Swap a path component while `AnchoredDir::open` resolves the path | Not defended, as in Go's `os.OpenRoot`: the path is followed once. The caller passes a cleaned absolute path and verifies the directory afterwards |

### GO-2026-6604

`CHANGELOG.md` says Go 1.27.4 carries "the Windows `os.Root` fix for GO-2026-6604". The advisory text could not be read offline. Secondary sources describe it as `Root.Mkdir`/`MkdirAll` following junctions out of the root on Windows, but those sources are unofficial and could not be confirmed against the Go vulnerability database; treat this as unverified. This design is not exposed to that class: it has no directory creation, never passes a multi-component name to the kernel, and opens every child with `FILE_OPEN_REPARSE_POINT`. The one multi-component resolution is the initial `AnchoredDir::open` (intended to follow links, like `os.OpenRoot`) and the `current_path_identity` check.

## Known limitations

- **FAT and exFAT:** no hard links (`link_noreplace` fails; see "Errors"), 64-bit identifiers are unstable across mounts, no POSIX delete (the fallback applies).
- **ReFS:** 64-bit file index is not guaranteed unique (see "Identity").
- **Network shares (SMB):** identity and delete semantics depend on the server; POSIX delete or hard links can be unsupported. Not tested.
- **Cloud-synced folders:** a directory with a cloud reparse tag is reported as a directory, and a file with one as `Other` (not regular); Go reports the same files as irregular.
- **Access-control lists** are not inspected. Windows keeps the inherited-ACL acknowledgement, as decided.
- **`GetFileInformationByHandleEx(FileAttributeTagInfo)`** is called only for handles that already report `FILE_ATTRIBUTE_REPARSE_POINT`, because some filesystems reject that class.

## `unsafe` blocks (for the specialist review)

`unsafe` exists only in `rust/platform/src/windows/` (`#![allow(unsafe_code)]` with a reason in `mod.rs`). Every block has a `// SAFETY:` comment. Lines are those of the commit that adds this file.

| File:line | Call | What the comment has to establish |
|---|---|---|
| `nt.rs:31` | `RtlNtStatusToDosError` | plain integer in and out |
| `nt.rs:138` | `NtCreateFile` | locals live across the call; `UNICODE_STRING.Length` is in bytes, without a terminator, checked to fit `u16` (`byte_len`); the kernel copies the name |
| `nt.rs:158` | `OwnedHandle::from_raw_handle` | handle came from a successful create and is owned exactly once |
| `nt.rs:216` | raw writes into `NameInfo` | zeroed 8-aligned `Vec<u64>` of at least `total` bytes; each write at a `offset_of!` offset inside it; name copy is `2 * units` bytes, equal to `FileNameLength` |
| `nt.rs:254` | `NtSetInformationFile` | only called from two safe wrappers that pass a reference's memory and its exact size |
| `meta.rs:33` | `GetFileInformationByHandle` | borrowed live handle, writable output struct |
| `meta.rs:47` | `GetFileInformationByHandleEx` | exact struct size for `FileAttributeTagInfo` |
| `meta.rs:125` | `GetFileType` | borrowed live handle |
| `file.rs:39` | `SetFileInformationByHandle` | exact struct size for `FileBasicInfo`; buffer is only read |
| `file.rs:63` | `GetStdHandle` | constant argument; result only compared, never closed |
| `file.rs:69` | `GetFileType` | a stale or invalid handle yields `FILE_TYPE_UNKNOWN`, not undefined behavior |
| `dir.rs:246` | `ReOpenFile` | live source handle, no pointers; result compared with `INVALID_HANDLE_VALUE` |
| `dir.rs:259` | `OwnedHandle::from_raw_handle` | new valid handle, owned once |
| `dir.rs:272` | `SetFileInformationByHandle` | exact struct size, buffer only read |

Handle ownership: every handle is an `OwnedHandle` (or a `File` built from one) immediately after creation, so it closes exactly once on every path, including error paths.

## Evidence (native Windows)

| Architecture | Runner image | Date | Run | Result |
|---|---|---|---|---|
| x64 | `windows-latest` | pending owner-run CI | | awaiting owner verification |
| arm64 | `windows-11-arm` | pending owner-run CI | | awaiting owner verification |

A Windows 11 ARM virtual machine run, if made, is supplemental. Emulated x64 results never close the task. Compile checks done on macOS: `cargo clippy -p lxmf-vanity-platform --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings` and the same with `aarch64-pc-windows-msvc`.
