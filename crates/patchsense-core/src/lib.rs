//! PatchSense core: lockfile parsing, vulnerability data, and priority scoring.
//!
//! This crate does not print to a terminal and does not depend on CLI crates.

pub mod error;
pub mod model;

pub use error::CoreError;
pub use model::{Advisory, Ecosystem, Finding, Package, ParsedLockfile, Report, Severity, Tier};

/// Crate version, shared with the `patchsense` binary.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
