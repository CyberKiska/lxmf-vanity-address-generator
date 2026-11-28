//! `--inspect`: public metadata of a 64-byte identity file. Port of inspect.go `inspectIdentity`.
//!
//! The file is looked up with `lstat`, opened without following a symlink and without blocking on
//! a FIFO, and checked again on the open handle (kind, same file, exactly 64 bytes) before any
//! byte is read. Nothing is ever written. The 65-byte read buffer is wiped on every path.
//!
//! Basis: the example rewrite's `inspect::read` flow, rebuilt on `AnchoredDir`, with Go's messages.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};

use lxmf_vanity_core::identity::{Identity, PublicIdentity};
use lxmf_vanity_platform::{FileKind, file_meta};
use zeroize::Zeroizing;

use crate::target_path::{TargetError, io_error_text, open_output_target, path_bytes};

/// Go's `identityPrivateKeySize`.
const IDENTITY_SIZE: usize = 64;

/// What an inspection found. Public data only, so it may be `Debug`.
#[derive(Debug)]
pub(crate) struct Inspected {
    pub(crate) public: PublicIdentity,
    /// The X25519 half was not in clamped form; the derivation clamped it, the file stays as it was.
    pub(crate) unmasked: bool,
    /// The file's name inside its directory (Go's `filepath.Base` of the path, which the text prints).
    pub(crate) name: OsString,
}

#[derive(Debug)]
pub(crate) enum InspectError {
    Target(TargetError),
    /// A failed system call; Go's `os.Root` names it `statat` or `openat` and the file name.
    Os {
        op: &'static str,
        name: OsString,
        source: io::Error,
    },
    NotRegular,
    NotRegularOf64Bytes,
    NotExactly64Bytes,
}

impl InspectError {
    /// Go's error text, byte for byte (the file name is raw bytes).
    pub(crate) fn message(&self) -> Vec<u8> {
        match self {
            InspectError::Target(e) => e.message(),
            InspectError::Os { op, name, source } => {
                let mut out = format!("{op} ").into_bytes();
                out.extend_from_slice(&path_bytes(name));
                out.extend_from_slice(b": ");
                out.extend_from_slice(io_error_text(source).as_bytes());
                out
            }
            InspectError::NotRegular => b"inspection input must be a regular file".to_vec(),
            InspectError::NotRegularOf64Bytes => {
                b"inspection input must be a regular file of exactly 64 bytes".to_vec()
            }
            InspectError::NotExactly64Bytes => {
                b"inspection input must contain exactly 64 bytes".to_vec()
            }
        }
    }
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.message()))
    }
}

impl std::error::Error for InspectError {}

impl From<TargetError> for InspectError {
    fn from(e: TargetError) -> Self {
        InspectError::Target(e)
    }
}

/// Port of `inspectIdentity`. Go joins the close errors of the file and the directory into the
/// result; closing a read-only descriptor cannot fail in a way that matters here, so they are dropped.
pub(crate) fn inspect_identity(path: &OsStr) -> Result<Inspected, InspectError> {
    let target = open_output_target(path)?;
    let name = target.name;
    let os_error = |op, source| InspectError::Os {
        op,
        name: name.clone(),
        source,
    };
    let entry = target.dir.lstat(&name).map_err(|e| os_error("statat", e))?;
    if entry.kind != FileKind::Regular {
        return Err(InspectError::NotRegular);
    }
    let mut file = target
        .dir
        .open_read_nofollow(&name)
        .map_err(|e| os_error("openat", e))?;
    // The directory path is the one Go joins into this message.
    let info = file_meta(&file).map_err(|e| InspectError::Os {
        op: "stat",
        name: target.dir.path().join(&name).into_os_string(),
        source: e,
    })?;
    if info.kind != FileKind::Regular || info.id != entry.id || info.size != IDENTITY_SIZE as u64 {
        return Err(InspectError::NotRegularOf64Bytes);
    }
    // One byte more than the identity, so that a file that grew is noticed.
    let mut raw = Zeroizing::new([0u8; IDENTITY_SIZE + 1]);
    let mut n = 0;
    let mut read_failed = false;
    while n < raw.len() {
        match file.read(&mut raw[n..]) {
            Ok(0) => break,
            Ok(read) => n += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                read_failed = true;
                break;
            }
        }
    }
    if n != IDENTITY_SIZE || read_failed {
        return Err(InspectError::NotExactly64Bytes);
    }
    let identity_bytes: &[u8; IDENTITY_SIZE] =
        raw.first_chunk().ok_or(InspectError::NotExactly64Bytes)?;
    // The derivation clamps a copy; the bytes read are never changed or written back.
    let (public, unmasked) = Identity::from_file_bytes(identity_bytes);
    Ok(Inspected {
        public,
        unmasked,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// A disposable directory inside the system temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "lxmf-vanity-inspect-{tag}-{}-{n}",
                std::process::id()
            ));
            fs::create_dir(&dir).expect("create the test directory");
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The public golden vector's unmasked input: bytes 0x00 to 0x3f.
    fn golden_raw() -> [u8; 64] {
        std::array::from_fn(|i| u8::try_from(i).expect("below 64"))
    }

    const GOLDEN_ADDRESS: [u8; 16] = [
        0xfa, 0xe3, 0x21, 0xc4, 0x42, 0xe3, 0xc9, 0xbd, 0xcd, 0x7a, 0x3e, 0x79, 0xd8, 0x50, 0xe0,
        0x3c,
    ];

    #[test]
    fn an_unmasked_golden_input_is_derived_and_reported_unmasked() {
        let dir = TempDir::new("raw");
        let path = dir.0.join("golden-public-fixture");
        fs::write(&path, golden_raw()).expect("write");
        let found = inspect_identity(path.as_os_str()).expect("valid input");
        assert_eq!(found.public.address, GOLDEN_ADDRESS);
        assert!(found.unmasked);
        assert_eq!(found.name, "golden-public-fixture");
        // Go: the input is never rewritten.
        assert_eq!(fs::read(&path).expect("read"), golden_raw());
    }

    #[test]
    fn a_masked_golden_input_is_not_reported_unmasked() {
        let dir = TempDir::new("masked");
        let path = dir.0.join("masked");
        let mut masked = golden_raw();
        masked[31] = 0x5f;
        fs::write(&path, masked).expect("write");
        let found = inspect_identity(path.as_os_str()).expect("valid input");
        assert_eq!(found.public.address, GOLDEN_ADDRESS);
        assert!(!found.unmasked);
    }

    #[test]
    fn wrong_sizes_and_directories_are_rejected_with_gos_messages() {
        let dir = TempDir::new("sizes");
        for size in [0usize, 1, 63, 65, 4096] {
            let path = dir.0.join(format!("size-{size}"));
            fs::write(&path, vec![7u8; size]).expect("write");
            let err = inspect_identity(path.as_os_str()).expect_err("wrong size");
            assert_eq!(
                err.to_string(),
                "inspection input must be a regular file of exactly 64 bytes",
                "size {size}"
            );
        }
        let sub = dir.0.join("folder");
        fs::create_dir(&sub).expect("mkdir");
        let err = inspect_identity(sub.as_os_str()).expect_err("directory");
        assert_eq!(err.to_string(), "inspection input must be a regular file");
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_file_names_the_system_call_and_the_name() {
        let dir = TempDir::new("missing");
        let err = inspect_identity(dir.0.join("absent").as_os_str()).expect_err("missing");
        assert_eq!(err.to_string(), "statat absent: no such file or directory");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_not_followed_even_when_it_points_to_a_valid_identity() {
        let dir = TempDir::new("symlink");
        fs::write(dir.0.join("real"), golden_raw()).expect("write");
        std::os::unix::fs::symlink("real", dir.0.join("link")).expect("symlink");
        let err = inspect_identity(dir.0.join("link").as_os_str()).expect_err("symlink");
        assert_eq!(err.to_string(), "inspection input must be a regular file");
    }

    #[test]
    fn a_path_that_names_no_file_is_a_target_error() {
        let err = inspect_identity(OsStr::new("..")).expect_err("no file");
        assert_eq!(err.to_string(), "output path must name a file");
    }
}
