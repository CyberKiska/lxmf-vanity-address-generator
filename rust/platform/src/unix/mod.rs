//! Unix adapter, built on `rustix` and `signal-hook`.

mod dir;

pub(crate) use dir::{Dir, RawFileId, file_meta};
