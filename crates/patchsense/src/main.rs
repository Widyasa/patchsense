//! PatchSense binary.

mod agent;
mod cli;
mod comment;
mod init;
mod mcp;
mod progress;
mod table;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rmcp::ServiceExt;

use patchsense_core::cache::{self, resolve_cache_db, Cache, CacheLocation};
use patchsense_core::config::{self, ExplainAgent, ExplainLang, FailOn, FlagInput, LoadRequest};
use patchsense_core::enrich::epss::epss_base_url;
use patchsense_core::enrich::kev::kev_feed_url;
use patchsense_core::http::{osv_base_url, ReqwestClient};
use patchsense_core::model::{Ecosystem, Report};
use patchsense_core::report::{render_gitlab, render_json, render_markdown, render_sarif};
use patchsense_core::scan::{scan_with, ScanOptions};

use crate::cli::{CacheCommand, Cli, Command, ReportFormat};

#[tokio::main]
async fn main() -> ExitCode {
    match try_main().await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

async fn try_main() -> anyhow::Result<ExitCode> {
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
            let fail_on = args.fail_on.as_deref().map(FailOn::parse).transpose()?;
            let agent = match args.agent.as_deref() {
                Some(value) => Some(ExplainAgent::parse(value)?),
                None => None,
            };
            let lang = match args.lang.as_deref() {
                Some("id") => Some(ExplainLang::Id),
                Some("en") => Some(ExplainLang::En),
                Some(other) => anyhow::bail!("unknown lang `{other}`"),
                None => None,
            };
            let config_env = std::env::var_os("PATCHSENSE_CONFIG").map(PathBuf::from);
            let mut loaded = config::load_config(&LoadRequest {
                start: &path,
                config_flag: args.config.as_deref(),
                config_env: config_env.as_deref(),
                today: &config::today_utc(),
                env: config::env_from_process()?,
                flags: FlagInput {
                    fail_on,
                    ecosystems,
                    include_dev: if args.no_dev { Some(false) } else { None },
                    // `auto` keeps the env/file choice, then PATH search.
                    agent: agent.filter(|choice| *choice != ExplainAgent::Auto),
                    exclude: args.exclude,
                },
            })?;
            if let Some(top) = args.explain_top {
                loaded.config.explain.top = top;
            }
            if let Some(lang) = lang {
                loaded.config.explain.lang = lang;
            }
            for warning in &loaded.warnings {
                eprintln!("warning: {warning}");
            }
            let plan = plan_outputs(&args.format, &args.output, progress::stdout_is_tty())?;
            let top = usize::try_from(loaded.config.output.top).unwrap_or(usize::MAX);
            let options = ScanOptions {
                keep_going: !args.no_keep_going,
                ecosystems: if loaded.config.scans_every_ecosystem() {
                    None
                } else {
                    Some(loaded.config.scan.ecosystems.clone())
                },
                no_dev: !loaded.config.scan.include_dev,
                offline: args.offline,
                no_cache: args.no_cache,
                cache_db: if args.no_cache {
                    None
                } else {
                    Some(cache_db_path(args.cache_dir.as_deref()))
                },
                now: None,
                excludes: loaded.config.scan.exclude.clone(),
                enrich: true,
                fail_on: loaded.config.scan.fail_on,
                score: loaded.config.score.clone(),
                ignore: loaded.config.ignore.clone(),
                epss_base_url: epss_base_url(),
                kev_feed_url: kev_feed_url(),
            };
            let client = ReqwestClient::new().context("failed to build the HTTP client")?;
            let progress = progress::start_scan_progress(progress::stderr_is_tty());
            let mut report = scan_with(&client, &osv_base_url(), &path, &options).await?;
            if let Some(bar) = &progress {
                bar.finish_and_clear();
            }
            if args.explain {
                let workdir = if path.is_dir() {
                    path.clone()
                } else {
                    path.parent().unwrap_or(Path::new(".")).to_path_buf()
                };
                let lang = match loaded.config.explain.lang {
                    ExplainLang::Id => agent::PromptLang::Id,
                    ExplainLang::En => agent::PromptLang::En,
                };
                agent::apply_explain(
                    &mut report,
                    &agent::ExplainRequest {
                        agent: loaded.config.explain.agent,
                        top: usize::try_from(loaded.config.explain.top).unwrap_or(usize::MAX),
                        lang,
                        timeout: std::time::Duration::from_secs(loaded.config.explain.timeout_secs),
                        workdir: &workdir,
                        path: None,
                    },
                );
            }
            write_reports(
                &report,
                &plan,
                args.no_color,
                args.min_score.unwrap_or(0),
                top,
            )?;
            if report.summary.failed {
                Ok(ExitCode::from(1))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        Command::Comment(args) => comment::run(args).await,
        Command::Mcp => {
            let running = mcp::McpServer
                .serve(rmcp::transport::stdio())
                .await
                .context("failed to start the MCP server")?;
            running
                .waiting()
                .await
                .context("MCP server stopped unexpectedly")?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Init(args) => {
            let status = init::write_example_config(Path::new("."), args.force)?;
            match status {
                init::InitStatus::Created => println!("wrote patchsense.toml"),
                init::InitStatus::Kept => {
                    println!("patchsense.toml already exists; pass --force to replace it");
                }
                init::InitStatus::Replaced => println!("replaced patchsense.toml"),
            }
            Ok(ExitCode::SUCCESS)
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
            Ok(ExitCode::SUCCESS)
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

/// One rendered report, either a file or stdout.
#[derive(Debug)]
struct PlannedOutput {
    format: ReportFormat,
    path: Option<PathBuf>,
}

/// Pair `--format` with `--output`.
///
/// Extra formats beyond the output list go to stdout. More than one stdout
/// format is an error. With no flags, a TTY gets `table` and anything else
/// gets `json`, both on stdout. A single `--output` without `--format` uses
/// that same default.
fn plan_outputs(
    formats: &[ReportFormat],
    outputs: &[PathBuf],
    stdout_tty: bool,
) -> anyhow::Result<Vec<PlannedOutput>> {
    let default_format = if stdout_tty {
        ReportFormat::Table
    } else {
        ReportFormat::Json
    };
    if formats.is_empty() {
        if outputs.len() > 1 {
            anyhow::bail!(
                "more than one --output was given without --format; pass one --format per file"
            );
        }
        return Ok(vec![PlannedOutput {
            format: default_format,
            path: outputs.first().cloned(),
        }]);
    }
    if outputs.len() > formats.len() {
        anyhow::bail!(
            "more --output values ({}) than --format values ({})",
            outputs.len(),
            formats.len()
        );
    }
    let stdout_count = formats.len() - outputs.len();
    if stdout_count > 1 {
        anyhow::bail!(
            "more than one --format would be written to stdout; pair each --format with --output"
        );
    }
    Ok(formats
        .iter()
        .enumerate()
        .map(|(index, format)| PlannedOutput {
            format: *format,
            path: outputs.get(index).cloned(),
        })
        .collect())
}

fn write_reports(
    report: &Report,
    plan: &[PlannedOutput],
    no_color: bool,
    min_score: u32,
    top: usize,
) -> anyhow::Result<()> {
    let mut shown = report.clone();
    shown.findings.retain(|finding| finding.score >= min_score);
    let stdout_tty = progress::stdout_is_tty();
    let no_color_env = std::env::var_os("NO_COLOR").is_some();
    for target in plan {
        let color =
            target.path.is_none() && progress::colors_enabled(no_color, no_color_env, stdout_tty);
        let text = render_format(&shown, target.format, color, top)?;
        match &target.path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)
                            .with_context(|| format!("failed to create {}", parent.display()))?;
                    }
                }
                std::fs::write(path, &text)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            None => print!("{text}"),
        }
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

fn render_format(
    report: &Report,
    format: ReportFormat,
    color: bool,
    top: usize,
) -> anyhow::Result<String> {
    match format {
        ReportFormat::Table => Ok(table::render_table(report, color, 0)),
        ReportFormat::Json => Ok(render_json(report)?),
        ReportFormat::Sarif => Ok(render_sarif(report)?),
        ReportFormat::Markdown => Ok(render_markdown(report, top)),
        ReportFormat::Gitlab => Ok(render_gitlab(report)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_non_tty_is_json_on_stdout() {
        let plan = plan_outputs(&[], &[], false).expect("plan");
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].format, ReportFormat::Json);
        assert!(plan[0].path.is_none());
    }

    #[test]
    fn default_tty_is_table_on_stdout() {
        let plan = plan_outputs(&[], &[], true).expect("plan");
        assert_eq!(plan[0].format, ReportFormat::Table);
        assert!(plan[0].path.is_none());
    }

    #[test]
    fn formats_pair_with_outputs_in_order() {
        let formats = [
            ReportFormat::Json,
            ReportFormat::Sarif,
            ReportFormat::Gitlab,
        ];
        let outputs = [
            PathBuf::from("a.json"),
            PathBuf::from("b.sarif"),
            PathBuf::from("c.json"),
        ];
        let plan = plan_outputs(&formats, &outputs, false).expect("plan");
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|item| item.path.is_some()));
        assert_eq!(plan[1].format, ReportFormat::Sarif);
        assert_eq!(plan[1].path.as_deref(), Some(outputs[1].as_path()));
    }

    #[test]
    fn one_unpaired_format_goes_to_stdout() {
        let formats = [ReportFormat::Json, ReportFormat::Markdown];
        let outputs = [PathBuf::from("a.json")];
        let plan = plan_outputs(&formats, &outputs, false).expect("plan");
        assert!(plan[0].path.is_some());
        assert_eq!(plan[1].format, ReportFormat::Markdown);
        assert!(plan[1].path.is_none());
    }

    #[test]
    fn two_formats_on_stdout_are_an_error() {
        let err = plan_outputs(&[ReportFormat::Json, ReportFormat::Sarif], &[], false)
            .expect_err("two stdout formats");
        assert!(err.to_string().contains("stdout"));
    }

    #[test]
    fn extra_output_is_an_error() {
        let err = plan_outputs(
            &[ReportFormat::Json],
            &[PathBuf::from("a.json"), PathBuf::from("b.json")],
            false,
        )
        .expect_err("extra output");
        assert!(err.to_string().contains("--output"));
    }
}
