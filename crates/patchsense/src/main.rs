//! PatchSense binary.

mod cli;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;

use patchsense_core::cache::{self, resolve_cache_db, Cache, CacheLocation};
use patchsense_core::http::{osv_base_url, ReqwestClient};
use patchsense_core::model::{Ecosystem, Report};
use patchsense_core::scan::{scan_with, ScanOptions};

use crate::cli::{CacheCommand, Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    match try_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

async fn try_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => {
            let path = args.path.unwrap_or_else(|| PathBuf::from("."));
            let ecosystems = if args.ecosystem.is_empty() {
                None
            } else {
                Some(
                    args.ecosystem
                        .iter()
                        .map(|name| Ecosystem::parse_config_name(name))
                        .collect::<Result<Vec<_>, _>>()?,
                )
            };
            let options = ScanOptions {
                keep_going: !args.no_keep_going,
                ecosystems,
                no_dev: args.no_dev,
                offline: args.offline,
                no_cache: args.no_cache,
                cache_db: if args.no_cache {
                    None
                } else {
                    Some(cache_db_path(args.cache_dir.as_deref()))
                },
                now: None,
            };
            let client = ReqwestClient::new().context("failed to build the HTTP client")?;
            let report = scan_with(&client, &osv_base_url(), &path, &options).await?;
            print_report(&report);
            Ok(())
        }
        Command::Cache(args) => {
            let path = cache_db_path(args.cache_dir.as_deref());
            match args.command {
                CacheCommand::Clear => {
                    let removed = cache::remove_cache_db(&path)?;
                    if removed {
                        println!("removed {}", path.display());
                    } else {
                        println!("no cache at {}", path.display());
                    }
                }
                CacheCommand::Info => {
                    if !path.is_file() {
                        println!("path: {}", path.display());
                        println!("status: absent");
                    } else {
                        let cache = Cache::open(&path)?;
                        let stats = cache.stats()?;
                        println!("path: {}", path.display());
                        println!("schema_version: {}", stats.schema_version);
                        println!("osv_vuln: {}", stats.osv_vuln);
                        println!("osv_query: {}", stats.osv_query);
                        println!("epss: {}", stats.epss);
                        println!("kev: {}", stats.kev);
                    }
                }
            }
            Ok(())
        }
    }
}

fn cache_db_path(flag: Option<&Path>) -> PathBuf {
    let env_cache = std::env::var_os("PATCHSENSE_CACHE_DIR").map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };
    resolve_cache_db(CacheLocation {
        flag,
        env_cache_dir: env_cache.as_deref(),
        xdg_cache_home: xdg.as_deref(),
        home: home.as_deref(),
        local_app_data: local.as_deref(),
        os,
    })
}

fn print_report(report: &Report) {
    for finding in &report.findings {
        let aliases = finding.advisory.aliases.join(",");
        let fixed = finding.advisory.fixed_versions.join(",");
        println!(
            "{}  {}@{}  {}  aliases={}  fixed={}  {}",
            finding.package.source_file,
            finding.package.name,
            finding.package.version,
            finding.advisory.id,
            aliases,
            fixed,
            finding.advisory.summary
        );
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
}
