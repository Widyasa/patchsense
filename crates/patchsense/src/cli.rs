//! Command line. Week 1 only implements `scan`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Prioritize vulnerabilities from lockfiles using OSV, EPSS, and CISA KEV.
#[derive(Debug, Parser)]
#[command(name = "patchsense", version, about, arg_required_else_help = true)]
pub struct Cli {
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// PatchSense commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan lockfiles and print matching advisories.
    Scan(ScanArgs),
}

/// Arguments for `patchsense scan`.
#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Directory or lockfile to scan. Defaults to the current directory.
    pub path: Option<PathBuf>,
}
