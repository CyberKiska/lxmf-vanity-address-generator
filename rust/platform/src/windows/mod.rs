//! Windows adapter, built on `windows-sys`.
//!
//! This is the only module in the workspace allowed to contain `unsafe`. The
//! crate root denies it; the allow below is needed because every NT file call
//! is a foreign function. The public API of the crate stays entirely safe:
//! each `unsafe` block sits in a private helper and carries a `// SAFETY:`
//! argument for pointer lifetime, buffer sizes, handle ownership and error
//! checking. `rust/platform/WINDOWS.md` lists the blocks and the design.
#![allow(
    unsafe_code,
    reason = "NT file calls and Win32 handle queries are foreign functions"
)]

mod dir;
mod file;
mod meta;
mod nt;

pub(crate) use dir::Dir;
pub(crate) use file::{
    effective_uid, harden_process, set_private_mode, stderr_is_char_device, sync_file,
};
pub(crate) use meta::{RawFileId, file_meta};

#[cfg(test)]
mod tests;
