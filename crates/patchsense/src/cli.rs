//! Command line. `scan` accepts keep-going and package filters.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

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
    /// Inspect or delete the local SQLite cache.
    Cache(CacheArgs),
    /// Write an example `patchsense.toml` in the current directory.
    Init(InitArgs),
    /// Create or update a pull-request comment from a JSON report.
    Comment(CommentArgs),
    /// Run the MCP server on stdio.
    Mcp,
}

/// Arguments for `patchsense cache`.
#[derive(Debug, Parser)]
pub struct CacheArgs {
    /// Directory that contains `cache.db`. Overrides `PATCHSENSE_CACHE_DIR`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// Cache subcommand.
    #[command(subcommand)]
    pub command: CacheCommand,
}

/// Arguments for `patchsense comment`.
#[derive(Debug, Parser)]
pub struct CommentArgs {
    /// JSON report from `patchsense scan --format json`.
    #[arg(long, value_name = "FILE")]
    pub report: PathBuf,

    /// `auto`, `github`, or `gitlab`. `auto` follows `GITHUB_ACTIONS` or `GITLAB_CI`.
    #[arg(long, value_name = "PROVIDER", default_value = "auto")]
    pub provider: String,

    /// Findings included in the comment table. Defaults to 20.
    #[arg(long, value_name = "N")]
    pub top: Option<usize>,

    /// Print the markdown and do not call the API.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for `patchsense init`.
#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Replace an existing `patchsense.toml`.
    #[arg(long)]
    pub force: bool,
}

/// `patchsense cache` subcommands.
#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Delete `cache.db`.
    Clear,
    /// Print the cache path, schema version, and row counts.
    Info,
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

    /// Use only the local cache. Do not call OSV.
    #[arg(long)]
    pub offline: bool,

    /// Do not read or write the cache.
    #[arg(long)]
    pub no_cache: bool,

    /// Directory that contains `cache.db`. Overrides `PATCHSENSE_CACHE_DIR`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// Path to `patchsense.toml`. Overrides discovery and `PATCHSENSE_CONFIG`.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Exit when a finding reaches this bar: critical, review, any, never, or 0-100.
    #[arg(long, value_name = "WHEN")]
    pub fail_on: Option<String>,

    /// Extra paths to skip. Repeatable. Added to `scan.exclude` from the config file.
    #[arg(long, action = ArgAction::Append)]
    pub exclude: Vec<String>,

    /// Hide findings below this score. Does not change the exit code.
    #[arg(long, value_name = "N")]
    pub min_score: Option<u32>,

    /// Do not color the table. Also honored when `NO_COLOR` is set.
    #[arg(long)]
    pub no_color: bool,

    /// Report format. Repeatable. Paired with `--output` in the same order.
    ///
    /// With no `--format`, a TTY gets `table` and a pipe or file gets `json`.
    #[arg(
        short = 'f',
        long = "format",
        value_enum,
        action = ArgAction::Append,
        value_name = "FORMAT"
    )]
    pub format: Vec<ReportFormat>,

    /// Write the paired `--format` to this file instead of stdout. Repeatable.
    #[arg(short = 'o', long = "output", action = ArgAction::Append, value_name = "FILE")]
    pub output: Vec<PathBuf>,
}

/// One scan report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Priority table.
    Table,
    /// PRD JSON report.
    Json,
    /// SARIF 2.1.0.
    Sarif,
    /// Markdown comment body.
    Markdown,
    /// GitLab dependency scanning report.
    Gitlab,
}
