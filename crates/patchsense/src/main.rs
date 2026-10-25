//! PatchSense binary.

mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;

use patchsense_core::http::{osv_base_url, ReqwestClient};
use patchsense_core::model::Report;
use patchsense_core::scan::scan_path;

use crate::cli::{Cli, Command};

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
            let client = ReqwestClient::new().context("failed to build the HTTP client")?;
            let report = scan_path(&client, &osv_base_url(), &path).await?;
            print_report(&report);
            Ok(())
        }
    }
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
