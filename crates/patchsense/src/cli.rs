//! Command line. `scan` accepts keep-going and package filters.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

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

    /// Continue after a lockfile fails to parse. This is the default.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "no_keep_going")]
    pub keep_going: bool,

    /// Stop at the first lockfile that cannot be read or parsed.
    #[arg(long, action = ArgAction::SetTrue, overrides_with = "keep_going")]
    pub no_keep_going: bool,

    /// Ecosystems to scan, comma-separated (`npm,pypi`). Repeatable.
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub ecosystem: Vec<String>,

    /// Skip dependencies the parser marked as dev.
    #[arg(long)]
    pub no_dev: bool,
}
