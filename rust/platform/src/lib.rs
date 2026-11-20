//! Operating-system adapters for lxmf-vanity.
//!
//! Unsafe code is denied here. Only `windows/` may opt in, with a written
//! justification for each use.
#![deny(unsafe_code)]

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
