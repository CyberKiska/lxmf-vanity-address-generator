//! Identity derivation and address matching for lxmf-vanity.
//!
//! This crate holds the secret-handling logic. It contains no `unsafe` code
//! and performs no input or output.
#![forbid(unsafe_code)]

pub mod identity;
pub mod matcher;
pub mod selftest;
