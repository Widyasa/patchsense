//! PatchSense library: lockfile parsing, vulnerability data, and priority scoring.
//!
//! `patchsense` is this library and the `patchsense` binary (`main.rs`).
//! Modules declared here do not print to a terminal and do not use `clap`,
//! `comfy-table`, `indicatif`, or `rmcp`.

pub mod cache;
pub mod config;
pub mod discovery;
pub mod enrich;
pub mod error;
pub mod go_imports;
pub mod http;
pub mod lockfile;
pub mod model;
pub mod osv;
pub mod report;
pub mod scan;
pub mod score;

pub use error::CoreError;
pub use model::{
    Advisory, Ecosystem, Finding, GoImport, Package, ParsedLockfile, Report, Severity, Tier,
};

/// Crate version, shared with the `patchsense` binary.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
