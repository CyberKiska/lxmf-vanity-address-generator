//! Process hardening; no `unsafe`.
//!
//! Basis: the example rewrite's hardening, which set both limits to 0 and
//! used libc. This is a port of harden_unix.go and harden_linux.go instead.

use crate::HardenError;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use std::io;

/// Port of harden_unix.go `hardenProcess`: lower only the soft core limit,
/// keep the hard one, then clear dumpability; collect every error.
pub(crate) fn harden_process() -> Result<(), HardenError> {
    let mut errors = Vec::new();
    // getrlimit cannot fail in rustix (it returns the limits directly).
    let limits = getrlimit(Resource::Core);
    let lowered = Rlimit {
        current: Some(0),
        maximum: limits.maximum,
    };
    if let Err(err) = setrlimit(Resource::Core, lowered) {
        errors.push(io::Error::from(err));
    }
    if let Err(err) = disable_dumpability() {
        errors.push(err);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HardenError::new(errors))
    }
}

// Port of harden_linux.go disableDumpability (PR_SET_DUMPABLE = 0).
#[cfg(target_os = "linux")]
fn disable_dumpability() -> io::Result<()> {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(io::Error::from)
}

// Port of harden_other_unix.go: nothing to do.
#[cfg(not(target_os = "linux"))]
fn disable_dumpability() -> io::Result<()> {
    Ok(())
}
