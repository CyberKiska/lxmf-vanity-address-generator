//! Unix adapter, built on `rustix` and `signal-hook`.

mod dir;
mod harden;

pub(crate) use dir::{Dir, RawFileId, file_meta};
pub(crate) use harden::{effective_uid, harden_process, stderr_is_char_device};
