//! Unix adapter, built on `rustix` and `signal-hook`.

mod dir;
mod harden;
mod write_stubs;

pub(crate) use dir::{Dir, RawFileId, file_meta};
pub(crate) use harden::{effective_uid, harden_process, stderr_is_char_device};
pub(crate) use write_stubs::{set_private_mode, sync_file};
