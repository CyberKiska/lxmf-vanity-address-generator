//! Output-path handling of Go's `openOutputTarget` (output.go) and the parts of
//! `path/filepath` it relies on: `Split`, `IsLocal`, `Clean`, `Dir` and `Abs`.
//!
//! The path functions work on bytes and take the operating system as a parameter,
//! so both rule sets are tested on every host. They are ports of
//! `internal/filepathlite` (Go 1.27.4): `Clean` and `Abs` are lexical and never
//! touch the file system, unlike `std::fs::canonicalize`; `std::path::absolute`
//! keeps `..` and is used only on Windows, where Go's `Abs` calls the same
//! `GetFullPathName` before it cleans.
//!
//! Basis: the example rewrite's `open_parent` (trailing-separator rule) and
//! Windows device-name check were cross-checks only; the code here follows Go.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::PathBuf;

use lxmf_vanity_platform::AnchoredDir;

/// Which path syntax to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathOs {
    Unix,
    Windows,
}

impl PathOs {
    pub(crate) const HOST: PathOs = if cfg!(windows) {
        PathOs::Windows
    } else {
        PathOs::Unix
    };
}

fn is_sep(os: PathOs, c: u8) -> bool {
    c == b'/' || (os == PathOs::Windows && c == b'\\')
}

fn separator(os: PathOs) -> u8 {
    match os {
        PathOs::Unix => b'/',
        PathOs::Windows => b'\\',
    }
}

fn from_slash(os: PathOs, path: &[u8]) -> Vec<u8> {
    let mut out = path.to_vec();
    if os == PathOs::Windows {
        for c in &mut out {
            if *c == b'/' {
                *c = b'\\';
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Volume names (Windows)
// ---------------------------------------------------------------------------------------

/// Port of `volumeNameLen`; zero on Unix.
fn volume_name_len(os: PathOs, path: &[u8]) -> usize {
    if os == PathOs::Unix {
        return 0;
    }
    if path.len() >= 2 && path[1] == b':' {
        // A drive letter. Go does not check the letter either.
        return 2;
    }
    if path.first().is_none_or(|&c| !is_sep(os, c)) {
        return 0;
    }
    if has_prefix_fold(path, br"\\.")
        || has_prefix_fold(path, br"\\?")
        || has_prefix_fold(path, br"\??")
    {
        // A device prefix: `\\.\`, `\\?\` or `\??\`.
        if path.len() == 3 {
            return 3;
        }
        let after = path.get(4..).unwrap_or_default();
        if has_prefix_fold(after, b"UNC") {
            return valid_volume_name_len(path, unc_len(path, br"\\.\UNC\".len()));
        }
        return match cut_path(after) {
            None => valid_volume_name_len(path, path.len()),
            Some((_, rest)) => valid_volume_name_len(path, path.len() - rest.len() - 1),
        };
    }
    if path.len() >= 2 && is_sep(os, path[1]) {
        return valid_volume_name_len(path, unc_len(path, 2));
    }
    0
}

/// `n` if `path[..n]` has no `..` component, else zero.
fn valid_volume_name_len(path: &[u8], n: usize) -> usize {
    let mut rest = &path[..n];
    while !rest.is_empty() {
        let (part, tail) = match cut_path(rest) {
            Some((part, tail)) => (part, tail),
            None => (rest, &[][..]),
        };
        if part == b".." {
            return 0;
        }
        rest = tail;
    }
    n
}

/// Case-insensitive prefix test where every separator matches every separator; when `s` is
/// longer than `prefix`, the next byte must be a separator.
fn has_prefix_fold(s: &[u8], prefix: &[u8]) -> bool {
    if s.len() < prefix.len() {
        return false;
    }
    for (&p, &c) in prefix.iter().zip(s) {
        if is_sep(PathOs::Windows, p) {
            if !is_sep(PathOs::Windows, c) {
                return false;
            }
        } else if !p.eq_ignore_ascii_case(&c) {
            return false;
        }
    }
    s.get(prefix.len())
        .is_none_or(|&c| is_sep(PathOs::Windows, c))
}

/// Length of the volume prefix of a UNC path: up to the second separator after the prefix.
fn unc_len(path: &[u8], prefix_len: usize) -> usize {
    let mut count = 0;
    for (i, &c) in path.iter().enumerate().skip(prefix_len) {
        if is_sep(PathOs::Windows, c) {
            count += 1;
            if count == 2 {
                return i;
            }
        }
    }
    path.len()
}

/// Splits around the first separator (either kind, as on Windows).
fn cut_path(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = path.iter().position(|&c| is_sep(PathOs::Windows, c))?;
    Some((&path[..i], &path[i + 1..]))
}

// ---------------------------------------------------------------------------------------
// Clean
// ---------------------------------------------------------------------------------------

/// Port of `lazybuf`. It keeps Go's quirk that the whole allocation, not only the first `w`
/// bytes, is visible to `postClean`.
struct LazyBuf<'a> {
    path: &'a [u8],
    buf: Option<Vec<u8>>,
    w: usize,
}

impl<'a> LazyBuf<'a> {
    fn new(path: &'a [u8]) -> Self {
        LazyBuf {
            path,
            buf: None,
            w: 0,
        }
    }

    fn index(&self, i: usize) -> u8 {
        match &self.buf {
            Some(buf) => buf.get(i).copied().unwrap_or(0),
            None => self.path.get(i).copied().unwrap_or(0),
        }
    }

    fn append(&mut self, c: u8) {
        if self.buf.is_none() {
            if self.path.get(self.w) == Some(&c) {
                self.w += 1;
                return;
            }
            let mut buf = vec![0u8; self.path.len()];
            buf[..self.w].copy_from_slice(&self.path[..self.w]);
            self.buf = Some(buf);
        }
        if let Some(buf) = &mut self.buf {
            match buf.get_mut(self.w) {
                Some(slot) => *slot = c,
                None => buf.push(c),
            }
            self.w += 1;
        }
    }

    fn prepend(&mut self, prefix: &[u8]) {
        if let Some(buf) = &mut self.buf {
            buf.splice(0..0, prefix.iter().copied());
            self.w += prefix.len();
        }
    }

    fn bytes(&self) -> &[u8] {
        match &self.buf {
            Some(buf) => &buf[..self.w.min(buf.len())],
            None => &self.path[..self.w.min(self.path.len())],
        }
    }
}

/// Port of `postClean`: stops a cleaned relative Windows path from turning into a drive-letter
/// or Root Local Device path.
fn post_clean(os: PathOs, vol_len: usize, out: &mut LazyBuf<'_>) {
    if os != PathOs::Windows || vol_len != 0 {
        return;
    }
    let Some(buf) = &out.buf else { return };
    for &c in buf {
        if is_sep(os, c) {
            break;
        }
        if c == b':' {
            out.prepend(b".\\");
            return;
        }
    }
    if buf.len() >= 3 && is_sep(os, buf[0]) && buf[1] == b'?' && buf[2] == b'?' {
        out.prepend(b"\\.");
    }
}

/// Port of `filepath.Clean`: purely lexical.
pub(crate) fn clean(os: PathOs, original: &[u8]) -> Vec<u8> {
    let vol_len = volume_name_len(os, original);
    let path = &original[vol_len..];
    if path.is_empty() {
        if vol_len > 1 && is_sep(os, original[0]) && is_sep(os, original[1]) {
            // A UNC volume name only.
            return from_slash(os, original);
        }
        let mut out = original.to_vec();
        out.push(b'.');
        return out;
    }
    let rooted = is_sep(os, path[0]);
    let sep = separator(os);
    let n = path.len();
    let mut out = LazyBuf::new(path);
    // `dotdot` is where `..` must stop: the leading separator or a leading `../..` prefix.
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.append(sep);
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if is_sep(os, path[r]) {
            r += 1; // an empty element
        } else if path[r] == b'.' && (r + 1 == n || is_sep(os, path[r + 1])) {
            r += 1; // a "." element
        } else if path[r] == b'.'
            && path.get(r + 1) == Some(&b'.')
            && (r + 2 == n || is_sep(os, path[r + 2]))
        {
            r += 2; // a ".." element: remove to the last separator
            if out.w > dotdot {
                out.w -= 1;
                while out.w > dotdot && !is_sep(os, out.index(out.w)) {
                    out.w -= 1;
                }
            } else if !rooted {
                // Cannot backtrack and not rooted: keep the "..".
                if out.w > 0 {
                    out.append(sep);
                }
                out.append(b'.');
                out.append(b'.');
                dotdot = out.w;
            }
        } else {
            if (rooted && out.w != 1) || (!rooted && out.w != 0) {
                out.append(sep);
            }
            while r < n && !is_sep(os, path[r]) {
                out.append(path[r]);
                r += 1;
            }
        }
    }
    if out.w == 0 {
        out.append(b'.');
    }
    post_clean(os, vol_len, &mut out);
    let mut result = original[..vol_len].to_vec();
    result.extend_from_slice(out.bytes());
    from_slash(os, &result)
}

// ---------------------------------------------------------------------------------------
// Split, Dir, IsLocal
// ---------------------------------------------------------------------------------------

/// Port of `filepath.Split`: the name is the text after the last separator.
pub(crate) fn split(os: PathOs, path: &[u8]) -> (&[u8], &[u8]) {
    let vol_len = volume_name_len(os, path);
    let mut i = path.len();
    while i > vol_len && !is_sep(os, path[i - 1]) {
        i -= 1;
    }
    path.split_at(i)
}

/// Port of `filepath.Dir`.
pub(crate) fn dir(os: PathOs, path: &[u8]) -> Vec<u8> {
    let vol_len = volume_name_len(os, path);
    let (head, _) = split(os, path);
    let cleaned = clean(os, &head[vol_len..]);
    let volume = from_slash(os, &path[..vol_len]);
    if cleaned == b"." && vol_len > 2 {
        // Must be UNC.
        return volume;
    }
    [volume, cleaned].concat()
}

/// Port of `filepath.IsLocal`.
pub(crate) fn is_local(os: PathOs, path: &[u8]) -> bool {
    match os {
        PathOs::Unix => unix_is_local(path),
        PathOs::Windows => windows_is_local(path),
    }
}

fn unix_is_local(path: &[u8]) -> bool {
    if path.is_empty() || path[0] == b'/' {
        return false;
    }
    let has_dots = path.split(|&c| c == b'/').any(|p| p == b"." || p == b"..");
    let cleaned: Cow<'_, [u8]> = if has_dots {
        Cow::Owned(clean(PathOs::Unix, path))
    } else {
        Cow::Borrowed(path)
    };
    !(cleaned.as_ref() == b".." || cleaned.starts_with(b"../"))
}

fn windows_is_local(path: &[u8]) -> bool {
    if path.is_empty() || is_sep(PathOs::Windows, path[0]) || path.contains(&b':') {
        // Empty, rooted in the current drive, or a colon (only valid after a drive letter).
        return false;
    }
    let mut has_dots = false;
    let mut rest = path;
    while !rest.is_empty() {
        let (part, tail) = match cut_path(rest) {
            Some((part, tail)) => (part, tail),
            None => (rest, &[][..]),
        };
        if part == b"." || part == b".." {
            has_dots = true;
        }
        if is_reserved_name(part) {
            return false;
        }
        rest = tail;
    }
    let cleaned: Cow<'_, [u8]> = if has_dots {
        Cow::Owned(clean(PathOs::Windows, path))
    } else {
        Cow::Borrowed(path)
    };
    !(cleaned.as_ref() == b".." || cleaned.starts_with(b"..\\"))
}

/// Port of `isReservedName`, stricter in one case. Go asks the system about a reserved name
/// that has an extension or trailing spaces (`CON.txt`, `NUL `, `NUL.`), through
/// `RtlIsDosDeviceName_U`, which Windows 11 no longer answers "reserved" for an extension.
/// A safe CLI crate cannot make that call, so those forms are reserved here
/// (`DEV-windows-reserved-extension`).
fn is_reserved_name(name: &[u8]) -> bool {
    // Device names can have arbitrary trailing characters after a dot or colon.
    let end = name
        .iter()
        .position(|&c| c == b':' || c == b'.')
        .unwrap_or(name.len());
    let mut base = &name[..end];
    // Trailing spaces in the last element are ignored.
    while let [rest @ .., b' '] = base {
        base = rest;
    }
    is_reserved_base_name(base)
}

fn is_reserved_base_name(name: &[u8]) -> bool {
    let upper = |i: usize| name.get(i).map_or(0, u8::to_ascii_uppercase);
    if name.len() == 3
        && matches!(
            &[upper(0), upper(1), upper(2)],
            b"CON" | b"PRN" | b"AUX" | b"NUL"
        )
    {
        return true;
    }
    if name.len() >= 4 && matches!(&[upper(0), upper(1), upper(2)], b"COM" | b"LPT") {
        if name.len() == 4 && (b'1'..=b'9').contains(&name[3]) {
            return true;
        }
        // The superscript digits are numbers as well (UTF-8 of U+00B2, U+00B3, U+00B9).
        return matches!(&name[3..], b"\xc2\xb2" | b"\xc2\xb3" | b"\xc2\xb9");
    }
    // CONIN$ and CONOUT$ open a console handle.
    name.eq_ignore_ascii_case(b"CONIN$") || name.eq_ignore_ascii_case(b"CONOUT$")
}

// ---------------------------------------------------------------------------------------
// Abs
// ---------------------------------------------------------------------------------------

/// Unix `Abs` given the working directory (the Windows host uses `GetFullPathName` instead;
/// the tests exercise this on every host): an absolute path is cleaned, a relative one is
/// joined to it and cleaned. `wd` is only asked for when needed, like Go.
#[cfg_attr(
    all(windows, not(test)),
    expect(dead_code, reason = "Windows asks GetFullPathName instead")
)]
fn abs_with_wd(
    path: &[u8],
    wd: impl FnOnce() -> Result<Vec<u8>, TargetError>,
) -> Result<Vec<u8>, TargetError> {
    if path.first() == Some(&b'/') {
        return Ok(clean(PathOs::Unix, path));
    }
    let wd = wd()?;
    if wd.is_empty() {
        return Ok(clean(PathOs::Unix, path));
    }
    Ok(clean(
        PathOs::Unix,
        &[wd, b"/".to_vec(), path.to_vec()].concat(),
    ))
}

/// Port of `os.Getwd` on Unix: `$PWD` when it is absolute and names the current directory,
/// else the system's answer.
#[cfg(unix)]
fn getwd() -> Result<Vec<u8>, TargetError> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    if let Some(pwd) = std::env::var_os("PWD").filter(|p| p.as_bytes().first() == Some(&b'/')) {
        let id = |p: &Path| {
            AnchoredDir::open(p)
                .and_then(|d| d.stat_self())
                .map(|m| m.id)
        };
        let dot = id(Path::new("."))
            .map_err(|e| TargetError::Cwd(format!("stat .: {}", io_error_text(&e)).into_bytes()))?;
        if id(Path::new(&pwd)).is_ok_and(|pwd_id| pwd_id == dot) {
            return Ok(pwd.as_bytes().to_vec());
        }
    }
    std::env::current_dir()
        .map(|d| d.as_os_str().as_bytes().to_vec())
        .map_err(|e| TargetError::Cwd(format!("getwd: {}", io_error_text(&e)).into_bytes()))
}

/// Port of `filepath.Abs` for the host.
#[cfg(unix)]
fn host_abs(path: &[u8]) -> Result<Vec<u8>, TargetError> {
    abs_with_wd(path, getwd)
}

/// Go calls `GetFullPathName` and cleans the result; `std::path::absolute` is the same call.
#[cfg(windows)]
fn host_abs(path: &[u8]) -> Result<Vec<u8>, TargetError> {
    let text = String::from_utf8_lossy(path);
    let text = if text.is_empty() {
        Cow::Borrowed(".")
    } else {
        text
    };
    let full = std::path::absolute(&*text)
        .map_err(|e| TargetError::Cwd(io_error_text(&e).into_bytes()))?;
    Ok(clean(PathOs::Windows, full.to_string_lossy().as_bytes()))
}

// ---------------------------------------------------------------------------------------
// OS strings and error text
// ---------------------------------------------------------------------------------------

/// The bytes Go sees for a path. On Windows Go decodes UTF-16 and replaces each unpaired
/// surrogate with U+FFFD, which `to_string_lossy` does too.
pub(crate) fn path_bytes(path: &OsStr) -> Cow<'_, [u8]> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Cow::Borrowed(path.as_bytes())
    }
    #[cfg(not(unix))]
    {
        match path.to_string_lossy() {
            Cow::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
            Cow::Owned(s) => Cow::Owned(s.into_bytes()),
        }
    }
}

/// The inverse of [`path_bytes`]. On Windows the bytes always came from lossy UTF-8.
fn os_from_bytes(bytes: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(bytes).to_os_string()
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Renders operating-system error text the way Go renders a `syscall.Errno`: without Rust's
/// ` (os error N)` suffix and, on Unix, with a lowercase first letter (`operation not
/// permitted`, not `Operation not permitted (os error 1)`). Go's tables for EPERM and EINVAL on
/// Linux and macOS read exactly that. Each line of a joined error is handled alone; a line that
/// is not an operating-system error stays as it is. On Windows only the suffix goes, because
/// Go keeps `FormatMessage`'s capitals and period there.
pub(crate) fn go_error_text(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            let Some(stem) = line.strip_suffix(')').and_then(|l| {
                let at = l.rfind(" (os error ")?;
                l[at + " (os error ".len()..]
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then_some(&l[..at])
            }) else {
                return line.to_owned();
            };
            let mut chars = stem.chars();
            match chars.next() {
                // "RPC struct is bad" keeps its capitals in Go; only a capitalized word shrinks.
                Some(first)
                    if cfg!(unix) && chars.clone().next().is_some_and(|c| !c.is_uppercase()) =>
                {
                    first.to_lowercase().chain(chars).collect()
                }
                _ => stem.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// [`go_error_text`] of an [`io::Error`].
pub(crate) fn io_error_text(err: &io::Error) -> String {
    go_error_text(&err.to_string())
}

// ---------------------------------------------------------------------------------------
// openOutputTarget
// ---------------------------------------------------------------------------------------

/// Why a target could not be opened. [`TargetError::message`] is Go's error text, byte for
/// byte (paths are raw bytes).
#[derive(Debug)]
pub(crate) enum TargetError {
    MustNameFile,
    /// The working directory could not be found; the text is already complete.
    Cwd(Vec<u8>),
    OpenDir {
        dir: Vec<u8>,
        source: io::Error,
    },
}

impl TargetError {
    pub(crate) fn message(&self) -> Vec<u8> {
        match self {
            TargetError::MustNameFile => b"output path must name a file".to_vec(),
            TargetError::Cwd(text) => text.clone(),
            TargetError::OpenDir { dir, source } => {
                // Go: "open output directory: " + the PathError of os.OpenRoot.
                let mut out = b"open output directory: open ".to_vec();
                out.extend_from_slice(dir);
                out.extend_from_slice(b": ");
                out.extend_from_slice(io_error_text(source).as_bytes());
                out
            }
        }
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.message()))
    }
}

impl std::error::Error for TargetError {}

/// A target file's directory, opened once, and its name inside it (Go's `outputTarget`
/// reduced to what inspection needs).
#[derive(Debug)]
pub(crate) struct OutputTarget {
    pub(crate) dir: AnchoredDir,
    /// The single path component of the file.
    pub(crate) name: OsString,
}

/// Port of `openOutputTarget`.
pub(crate) fn open_output_target(path: &OsStr) -> Result<OutputTarget, TargetError> {
    let os = PathOs::HOST;
    let bytes = path_bytes(path);
    let (_, name) = split(os, &bytes);
    if name == b"." || !is_local(os, name) {
        return Err(TargetError::MustNameFile);
    }
    let absolute = host_abs(&bytes)?;
    let directory = dir(os, &absolute);
    match AnchoredDir::open(&PathBuf::from(os_from_bytes(&directory))) {
        Ok(dir) => Ok(OutputTarget {
            dir,
            name: os_from_bytes(name),
        }),
        Err(source) => Err(TargetError::OpenDir {
            dir: directory,
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIX: PathOs = PathOs::Unix;
    const WIN: PathOs = PathOs::Windows;

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).expect("test paths are UTF-8")
    }

    // Go: path/filepath TestClean (`cleantests`, `wincleantests`; Go 1.27.4 path_test.go)
    const CLEAN_TESTS: &[(&str, &str)] = &[
        ("abc", "abc"),
        ("abc/def", "abc/def"),
        ("a/b/c", "a/b/c"),
        (".", "."),
        ("..", ".."),
        ("../..", "../.."),
        ("../../abc", "../../abc"),
        ("/abc", "/abc"),
        ("/", "/"),
        ("", "."),
        ("abc/", "abc"),
        ("abc/def/", "abc/def"),
        ("a/b/c/", "a/b/c"),
        ("./", "."),
        ("../", ".."),
        ("../../", "../.."),
        ("/abc/", "/abc"),
        ("abc//def//ghi", "abc/def/ghi"),
        ("abc//", "abc"),
        ("abc/./def", "abc/def"),
        ("/./abc/def", "/abc/def"),
        ("abc/.", "abc"),
        ("abc/def/ghi/../jkl", "abc/def/jkl"),
        ("abc/def/../ghi/../jkl", "abc/jkl"),
        ("abc/def/..", "abc"),
        ("abc/def/../..", "."),
        ("/abc/def/../..", "/"),
        ("abc/def/../../..", ".."),
        ("/abc/def/../../..", "/"),
        ("abc/def/../../../ghi/jkl/../../../mno", "../../mno"),
        ("/../abc", "/abc"),
        ("a/../b:/../../c", "../c"),
        ("abc/./../def", "def"),
        ("abc//./../def", "def"),
        ("abc/../../././../def", "../../def"),
    ];

    const WIN_CLEAN_TESTS: &[(&str, &str)] = &[
        ("c:", "c:."),
        ("c:\\", "c:\\"),
        ("c:\\abc", "c:\\abc"),
        ("c:abc\\..\\..\\.\\.\\..\\def", "c:..\\..\\def"),
        ("c:\\abc\\def\\..\\..", "c:\\"),
        ("c:\\..\\abc", "c:\\abc"),
        ("c:..\\abc", "c:..\\abc"),
        ("c:\\b:\\..\\..\\..\\d", "c:\\d"),
        ("\\", "\\"),
        ("/", "\\"),
        ("\\\\i\\..\\c$", "\\c$"),
        ("\\\\i\\..\\i\\c$", "\\i\\c$"),
        ("\\\\i\\..\\I\\c$", "\\I\\c$"),
        ("\\\\..\\..\\a", "\\a"),
        ("//../../a", "\\a"),
        ("\\\\host\\share\\foo\\..\\bar", "\\\\host\\share\\bar"),
        ("//host/share/foo/../baz", "\\\\host\\share\\baz"),
        (
            "\\\\host\\share\\foo\\..\\..\\..\\..\\bar",
            "\\\\host\\share\\bar",
        ),
        (
            "\\\\?\\UNC\\host\\share\\foo\\..\\..\\..\\..\\bar",
            "\\\\?\\UNC\\host\\share\\bar",
        ),
        (
            "\\??\\UNC\\host\\share\\foo\\..\\..\\..\\..\\bar",
            "\\??\\UNC\\host\\share\\bar",
        ),
        ("\\\\.\\C:\\a\\..\\..\\..\\..\\bar", "\\\\.\\C:\\bar"),
        ("\\\\.\\C:\\\\\\\\a", "\\\\.\\C:\\a"),
        ("\\\\a\\b\\..\\c", "\\\\a\\b\\c"),
        ("\\\\a\\b", "\\\\a\\b"),
        (".\\c:", ".\\c:"),
        (".\\c:\\foo", ".\\c:\\foo"),
        (".\\c:foo", ".\\c:foo"),
        ("//abc", "\\\\abc"),
        ("///abc", "\\\\\\abc"),
        ("//abc//", "\\\\abc\\\\"),
        ("\\\\?\\C:\\", "\\\\?\\C:\\"),
        ("\\\\?\\C:\\a", "\\\\?\\C:\\a"),
        // Cleaning must not move an element with a colon to the start of the path.
        ("a/../c:", ".\\c:"),
        ("a\\..\\c:", ".\\c:"),
        ("a/../c:/a", ".\\c:\\a"),
        ("a/../../c:", "..\\c:"),
        ("foo:bar", "foo:bar"),
        // Nor create a Root Local Device path like `\??\a`.
        ("/a/../??/a", "\\.\\??\\a"),
    ];

    #[test]
    fn clean_matches_go_on_unix() {
        for (path, want) in CLEAN_TESTS {
            assert_eq!(text(clean(UNIX, path.as_bytes())), *want, "Clean({path:?})");
        }
    }

    #[test]
    fn clean_matches_go_on_windows() {
        for (path, want) in CLEAN_TESTS {
            let want = want.replace('/', "\\");
            assert_eq!(text(clean(WIN, path.as_bytes())), want, "Clean({path:?})");
        }
        for (path, want) in WIN_CLEAN_TESTS {
            assert_eq!(text(clean(WIN, path.as_bytes())), *want, "Clean({path:?})");
        }
    }

    // Go: path/filepath TestSplit (`unixsplittests`, `winsplittests`)
    #[test]
    fn split_matches_go_on_both_systems() {
        let unix = [
            ("a/b", "a/", "b"),
            ("a/b/", "a/b/", ""),
            ("a/", "a/", ""),
            ("a", "", "a"),
            ("/", "/", ""),
        ];
        for (path, dir, file) in unix {
            let (d, f) = split(UNIX, path.as_bytes());
            assert_eq!((d, f), (dir.as_bytes(), file.as_bytes()), "Split({path:?})");
        }
        let windows = [
            ("c:", "c:", ""),
            ("c:/", "c:/", ""),
            ("c:/foo", "c:/", "foo"),
            ("c:/foo/bar", "c:/foo/", "bar"),
            ("//host/share", "//host/share", ""),
            ("//host/share/", "//host/share/", ""),
            ("//host/share/foo", "//host/share/", "foo"),
            ("\\\\host\\share", "\\\\host\\share", ""),
            ("\\\\host\\share\\", "\\\\host\\share\\", ""),
            ("\\\\host\\share\\foo", "\\\\host\\share\\", "foo"),
        ];
        for (path, dir, file) in windows {
            let (d, f) = split(WIN, path.as_bytes());
            assert_eq!((d, f), (dir.as_bytes(), file.as_bytes()), "Split({path:?})");
        }
        // Windows accepts both separators; Unix only the slash.
        assert_eq!(split(WIN, b"a\\b/c").1, b"c");
        assert_eq!(split(WIN, b"a/b\\c").1, b"c");
        assert_eq!(split(UNIX, b"a/b\\c").1, b"b\\c");
    }

    #[test]
    fn dir_cleans_the_head_like_go() {
        assert_eq!(text(dir(UNIX, b"/a/b/c")), "/a/b");
        assert_eq!(text(dir(UNIX, b"/a/b/")), "/a/b");
        assert_eq!(text(dir(UNIX, b"/a")), "/");
        assert_eq!(text(dir(UNIX, b"a")), ".");
        assert_eq!(text(dir(UNIX, b"/a//b/../c")), "/a");
        assert_eq!(text(dir(WIN, b"C:\\a\\b")), "C:\\a");
        assert_eq!(text(dir(WIN, b"C:\\a")), "C:\\");
        assert_eq!(text(dir(WIN, b"\\\\host\\share\\f")), "\\\\host\\share\\");
        assert_eq!(text(dir(WIN, b"\\\\host\\share")), "\\\\host\\share");
    }

    // Go: path/filepath TestIsLocal (`islocaltests`, `winislocaltests`)
    const LOCAL_TESTS: &[(&str, bool)] = &[
        ("", false),
        (".", true),
        ("..", false),
        ("../a", false),
        ("/", false),
        ("/a", false),
        ("/a/../..", false),
        ("a", true),
        ("a/../a", true),
        ("a/", true),
        ("a/.", true),
        ("a/./b/./c", true),
        ("a/../b:/../../c", false),
    ];

    const WIN_LOCAL_TESTS: &[(&str, bool)] = &[
        ("NUL", false),
        ("nul", false),
        ("nul ", false),
        ("nul.", false),
        ("a/nul:", false),
        ("a/nul : a", false),
        ("com0", true),
        ("com1", false),
        ("com2", false),
        ("com3", false),
        ("com4", false),
        ("com5", false),
        ("com6", false),
        ("com7", false),
        ("com8", false),
        ("com9", false),
        ("com\u{b9}", false),
        ("com\u{b2}", false),
        ("com\u{b3}", false),
        ("com\u{b9} : a", false),
        ("cOm1", false),
        ("lpt1", false),
        ("LPT1", false),
        ("lpt\u{b3}", false),
        ("./nul", false),
        ("\\", false),
        ("\\a", false),
        ("C:", false),
        ("C:\\a", false),
        ("..\\a", false),
        ("a/../c:", false),
        ("CONIN$", false),
        ("conin$", false),
        ("CONOUT$", false),
        ("conout$", false),
        ("dollar$", true), // not a special file name
    ];

    #[test]
    fn is_local_matches_go_on_unix() {
        for (path, want) in LOCAL_TESTS {
            assert_eq!(is_local(UNIX, path.as_bytes()), *want, "IsLocal({path:?})");
        }
    }

    #[test]
    fn is_local_matches_go_on_windows() {
        for (path, want) in LOCAL_TESTS.iter().chain(WIN_LOCAL_TESTS) {
            assert_eq!(is_local(WIN, path.as_bytes()), *want, "IsLocal({path:?})");
        }
    }

    #[test]
    fn windows_reserved_names_with_extension_or_spaces_are_refused() {
        // Go asks Windows about these; this build refuses all of them
        // (DEV-windows-reserved-extension).
        for name in [
            "CON.txt",
            "con.tar.gz",
            "NUL.",
            "NUL ",
            "nul  .x",
            "COM1.txt",
            "lpt\u{b2}.log",
            "CONIN$.x",
        ] {
            assert!(!is_local(WIN, name.as_bytes()), "{name:?}");
        }
        for name in [
            "CONSOLE", "NULL", "COM10", "COM", "LPT0", "xcon", "con-1", "a.con",
        ] {
            assert!(is_local(WIN, name.as_bytes()), "{name:?}");
        }
        // On Unix none of this applies.
        assert!(is_local(UNIX, b"NUL"));
        assert!(is_local(UNIX, b"CON.txt"));
    }

    #[test]
    fn a_file_name_with_a_colon_is_local_on_unix_only() {
        assert!(is_local(UNIX, b"a:b"));
        assert!(!is_local(WIN, b"a:b"));
    }

    fn abs(path: &str, wd: &str) -> String {
        text(abs_with_wd(path.as_bytes(), || Ok(wd.as_bytes().to_vec())).expect("no error"))
    }

    // Go: filepath.Abs is Join(Getwd(), path) for a relative path, and Clean resolves `..`
    // without touching the file system.
    #[test]
    fn abs_resolves_dotdot_lexically() {
        assert_eq!(abs("key", "/w"), "/w/key");
        assert_eq!(abs("a/b/../key", "/w"), "/w/a/key");
        assert_eq!(abs("../key", "/w/x"), "/w/key");
        assert_eq!(abs("../../../key", "/w"), "/key");
        assert_eq!(abs("./a/./b", "/"), "/a/b");
        assert_eq!(abs("/a/../b/./c", "/never"), "/b/c");
        assert_eq!(abs("a//b", "/w//x/"), "/w/x/a/b");
    }

    #[test]
    fn abs_of_an_absolute_path_does_not_ask_for_the_working_directory() {
        let got = abs_with_wd(b"/a/b", || Err(TargetError::Cwd(b"asked".to_vec())));
        assert_eq!(text(got.expect("no wd needed")), "/a/b");
    }

    #[test]
    fn a_working_directory_failure_is_reported_with_its_text() {
        let err = abs_with_wd(b"a", || Err(TargetError::Cwd(b"getwd: boom".to_vec())))
            .expect_err("fails");
        assert_eq!(err.to_string(), "getwd: boom");
    }

    #[test]
    fn go_error_text_drops_the_suffix_and_the_capital() {
        let cases = [
            (
                "Operation not permitted (os error 1)",
                "operation not permitted",
            ),
            ("Invalid argument (os error 22)", "invalid argument"),
            (
                "No such file or directory (os error 2)",
                "no such file or directory",
            ),
            ("RPC struct is bad (os error 72)", "RPC struct is bad"),
            ("plain text", "plain text"),
            (
                "Operation not permitted (os error x)",
                "Operation not permitted (os error x)",
            ),
        ];
        for (rust, go) in cases {
            if cfg!(unix) {
                assert_eq!(go_error_text(rust), go);
            } else {
                assert_eq!(go_error_text(rust).to_lowercase(), go.to_lowercase());
            }
        }
        // Joined errors: one line each.
        let joined =
            go_error_text("Operation not permitted (os error 1)\nInvalid argument (os error 22)");
        assert_eq!(
            joined.to_lowercase(),
            "operation not permitted\ninvalid argument"
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_errno_text_reads_like_gos_table() {
        // Go: syscall.EPERM, ENOENT and EINVAL on linux and darwin.
        for (errno, want) in [
            (1, "operation not permitted"),
            (2, "no such file or directory"),
            (22, "invalid argument"),
        ] {
            assert_eq!(io_error_text(&io::Error::from_raw_os_error(errno)), want);
        }
    }

    #[test]
    fn a_path_that_does_not_name_a_file_is_refused_before_any_file_access() {
        for path in [".", "..", "a/..", "/", "a/", "a/.", "/a/..", "./", ""] {
            let err = open_output_target(OsStr::new(path)).expect_err(path);
            assert_eq!(err.to_string(), "output path must name a file", "{path:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_directory_gives_the_open_error_with_the_cleaned_directory() {
        let err = open_output_target(OsStr::new("/lxmf-vanity-no-such-dir/sub/../x"))
            .expect_err("missing");
        assert_eq!(
            err.to_string(),
            "open output directory: open /lxmf-vanity-no-such-dir: no such file or directory"
        );
    }

    #[test]
    fn an_existing_directory_opens_and_keeps_the_name() {
        let path = std::env::temp_dir().join("some-name");
        let target = open_output_target(path.as_os_str()).expect("the temp dir exists");
        assert_eq!(target.name, OsStr::new("some-name"));
    }
}
