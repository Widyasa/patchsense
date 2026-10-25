//! Read-only MCP server on stdio. Protocol bytes stay on stdout.
//!
//! Scans use the same config, cache, and HTTP client as `patchsense scan`.
//! Tool text is the only stdout. Warnings from config loading go to stderr.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use patchsense_core::cache::{resolve_cache_db, CacheLocation};
use patchsense_core::config::{self, FlagInput, LoadRequest};
use patchsense_core::enrich::epss::epss_base_url;
use patchsense_core::enrich::kev::kev_feed_url;
use patchsense_core::http::{osv_base_url, ReqwestClient};
use patchsense_core::lockfile::{parser_for, supported_file_names};
use patchsense_core::model::{Ecosystem, Finding, Report, Tier};
use patchsense_core::report::{render_json, render_markdown};
use patchsense_core::scan::{minimum_covering_fix, scan_with, ScanOptions};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::handler::server::ServerHandler;
use rmcp::{tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

/// Findings returned by `scan_project`. The summary still counts every finding.
pub(crate) const SCAN_PROJECT_LIMIT: usize = 50;

/// MCP server. Tools scan on demand and do not change the project.
#[derive(Debug, Clone, Default)]
pub struct McpServer;

#[derive(Debug, Deserialize, JsonSchema)]
struct ScanProjectParams {
    /// Directory or lockfile to scan. Defaults to `.`.
    #[serde(default)]
    path: Option<String>,
    /// Ecosystem names. Empty scans every ecosystem the config allows.
    #[serde(default)]
    ecosystems: Vec<String>,
    /// Drop findings below this score. `0` keeps every finding.
    #[serde(default)]
    min_score: u32,
    /// When set, overrides `include_dev` from config.
    #[serde(default)]
    include_dev: Option<bool>,
    /// Skip the network and use the cache only.
    #[serde(default)]
    offline: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingParams {
    /// GHSA, CVE, or other advisory id.
    id: String,
    /// Directory or lockfile to scan. Defaults to `.`.
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FixPlanParams {
    /// Directory or lockfile to scan. Defaults to `.`.
    #[serde(default)]
    path: Option<String>,
    /// `critical`, `review`, or `defer`. Empty includes every tier.
    #[serde(default)]
    tier: Option<String>,
}

#[tool_router]
impl McpServer {
    /// Lockfile names this build can parse, with their OSV ecosystems.
    #[tool(
        description = "List lockfile names PatchSense can parse and their OSV ecosystems",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn list_supported_lockfiles(&self) -> String {
        let rows: Vec<_> = supported_file_names()
            .into_iter()
            .map(|name| {
                let ecosystem = parser_for(Path::new(name))
                    .map(|parser| parser.ecosystem().as_osv_str())
                    .unwrap_or("unknown");
                json!({ "file": name, "ecosystem": ecosystem })
            })
            .collect();
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
    }

    /// Scan a project and return markdown plus the JSON report.
    #[tool(
        description = "Scan lockfiles and return the top 50 findings plus the full summary",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn scan_project(
        &self,
        Parameters(params): Parameters<ScanProjectParams>,
    ) -> Result<String, String> {
        let path = params.path.unwrap_or_else(|| ".".to_string());
        let report = scan_project_at(
            Path::new(&path),
            &params.ecosystems,
            params.include_dev,
            params.offline,
        )
        .await?;
        Ok(present_scan(&report, params.min_score))
    }

    /// One advisory, including score signals.
    #[tool(
        description = "Return one advisory by GHSA, CVE, or OSV id",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn get_finding(
        &self,
        Parameters(params): Parameters<FindingParams>,
    ) -> Result<String, String> {
        let finding = find_one(&params.id, params.path.as_deref()).await?;
        let cvss = finding
            .signals
            .cvss
            .as_ref()
            .map(|item| json!({ "base_score": item.base_score, "vector": item.vector, "source": item.source }));
        let body = json!({
            "id": finding.advisory.id,
            "summary": finding.advisory.summary,
            "aliases": finding.advisory.aliases,
            "fixed_versions": finding.advisory.fixed_versions,
            "references": finding.advisory.references,
            "cves": finding.signals.cves,
            "cvss": cvss,
            "epss": finding.signals.epss,
            "kev": finding.signals.kev,
            "score": finding.score,
            "tier": finding.tier.label_id(),
            "score_breakdown": finding.signals.breakdown,
            "package": {
                "ecosystem": finding.package.ecosystem.as_osv_str(),
                "name": finding.package.name,
                "version": finding.package.version,
            },
        });
        Ok(serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".to_string()))
    }

    /// One upgrade per package. The command in `manifest_hint` is not run.
    #[tool(
        description = "Recommend the minimum upgrade that covers every advisory on a package",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn get_fix_plan(
        &self,
        Parameters(params): Parameters<FixPlanParams>,
    ) -> Result<String, String> {
        let path = params.path.unwrap_or_else(|| ".".to_string());
        let tier = match params
            .tier
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => Some(parse_tier(value)?),
            None => None,
        };
        let report = scan_project_at(Path::new(&path), &[], None, false).await?;
        let rows = fix_plan(&report, tier);
        serde_json::to_string_pretty(&rows).map_err(|err| err.to_string())
    }

    /// Deterministic score explanation. This does not call an agent.
    #[tool(
        description = "Explain a finding score from its components, weights, and thresholds",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn explain_score(
        &self,
        Parameters(params): Parameters<FindingParams>,
    ) -> Result<String, String> {
        let finding = find_one(&params.id, params.path.as_deref()).await?;
        Ok(explain_finding(&finding))
    }
}

#[tool_handler(
    name = "patchsense",
    instructions = "Read-only lockfile triage. Logs stay on stderr. scan_project returns at most 50 findings."
)]
impl ServerHandler for McpServer {}

async fn scan_project_at(
    path: &Path,
    ecosystems: &[String],
    include_dev: Option<bool>,
    offline: bool,
) -> Result<Report, String> {
    let parsed = if ecosystems.is_empty() {
        None
    } else {
        let mut names = Vec::with_capacity(ecosystems.len());
        for name in ecosystems {
            names.push(Ecosystem::parse_config_name(name).map_err(|err| err.to_string())?);
        }
        Some(names)
    };
    let config_env = std::env::var_os("PATCHSENSE_CONFIG").map(PathBuf::from);
    let loaded = config::load_config(&LoadRequest {
        start: path,
        config_flag: None,
        config_env: config_env.as_deref(),
        today: &config::today_utc(),
        env: config::env_from_process().map_err(|err| err.to_string())?,
        flags: FlagInput {
            fail_on: None,
            ecosystems: parsed,
            include_dev,
            agent: None,
            exclude: Vec::new(),
        },
    })
    .map_err(|err| err.to_string())?;
    for warning in &loaded.warnings {
        eprintln!("warning: {warning}");
    }
    let options = ScanOptions {
        keep_going: true,
        ecosystems: if loaded.config.scans_every_ecosystem() {
            None
        } else {
            Some(loaded.config.scan.ecosystems.clone())
        },
        no_dev: !loaded.config.scan.include_dev,
        offline,
        no_cache: false,
        cache_db: Some(cache_db_path()),
        now: None,
        excludes: loaded.config.scan.exclude.clone(),
        enrich: true,
        fail_on: loaded.config.scan.fail_on,
        score: loaded.config.score.clone(),
        ignore: loaded.config.ignore.clone(),
        epss_base_url: epss_base_url(),
        kev_feed_url: kev_feed_url(),
    };
    let client = ReqwestClient::new().map_err(|err| err.to_string())?;
    scan_with(&client, &osv_base_url(), path, &options)
        .await
        .map_err(|err| err.to_string())
}

fn cache_db_path() -> PathBuf {
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
        flag: None,
        env_cache_dir: env_cache.as_deref(),
        xdg_cache_home: xdg.as_deref(),
        home: home.as_deref(),
        local_app_data: local.as_deref(),
        os,
    })
}

/// Markdown plus the JSON report. Findings below `min_score` are omitted, then
/// the list is cut at [`SCAN_PROJECT_LIMIT`]. `summary` stays the full scan.
pub(crate) fn present_scan(report: &Report, min_score: u32) -> String {
    let mut shown = report.clone();
    shown.findings.retain(|finding| finding.score >= min_score);
    for finding in &mut shown.findings {
        finding.signals.explanation = None;
    }
    let matched = shown.findings.len();
    let truncated = matched > SCAN_PROJECT_LIMIT;
    if truncated {
        shown.findings.truncate(SCAN_PROJECT_LIMIT);
    }
    let mut header = String::new();
    if truncated {
        header.push_str(&format!(
            "Menampilkan {SCAN_PROJECT_LIMIT} dari {matched} temuan.\n\n"
        ));
    }
    if min_score > 0 {
        header.push_str(&format!("Filter skor minimum: {min_score}.\n\n"));
    }
    let markdown = render_markdown(&shown, SCAN_PROJECT_LIMIT);
    let json = render_json(&shown).unwrap_or_else(|err| format!("error: {err}"));
    format!("{header}{markdown}\n## JSON\n\n```json\n{json}\n```\n")
}

async fn find_one(id: &str, path: Option<&str>) -> Result<Finding, String> {
    let path = path.unwrap_or(".");
    let report = scan_project_at(Path::new(path), &[], None, false).await?;
    report
        .findings
        .into_iter()
        .find(|finding| finding_matches(finding, id))
        .ok_or_else(|| format!("finding not found: {id}"))
}

fn finding_matches(finding: &Finding, id: &str) -> bool {
    let needle = id.trim();
    finding.advisory.id.eq_ignore_ascii_case(needle)
        || finding
            .advisory
            .aliases
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(needle))
        || finding
            .signals
            .cves
            .iter()
            .any(|cve| cve.eq_ignore_ascii_case(needle))
}

fn parse_tier(value: &str) -> Result<Tier, String> {
    match value.to_ascii_lowercase().as_str() {
        "critical" | "kritis" => Ok(Tier::Critical),
        "review" | "perlu dicek" => Ok(Tier::Review),
        "defer" | "bisa ditunda" => Ok(Tier::Defer),
        other => Err(format!("unknown tier: {other}")),
    }
}

/// One row of `get_fix_plan`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct FixPlanRow {
    /// OSV ecosystem name.
    pub ecosystem: String,
    /// Package name.
    pub name: String,
    /// Installed version.
    pub current: String,
    /// Minimum version that covers every advisory. Absent when no such version is known.
    pub recommended: Option<String>,
    /// Advisory ids included in the plan.
    pub advisories: Vec<String>,
    /// A command the user can run. PatchSense does not execute it.
    pub manifest_hint: String,
}

type PackageKey = (String, String, String);
type AdvisoryFixes = (Vec<String>, Vec<Vec<String>>);

/// Group findings by package and pick [`minimum_covering_fix`].
pub(crate) fn fix_plan(report: &Report, tier: Option<Tier>) -> Vec<FixPlanRow> {
    let mut groups: BTreeMap<PackageKey, AdvisoryFixes> = BTreeMap::new();
    for finding in &report.findings {
        if tier.is_some_and(|wanted| finding.tier != wanted) {
            continue;
        }
        let key = (
            finding.package.ecosystem.as_osv_str().to_string(),
            finding.package.name.clone(),
            finding.package.version.clone(),
        );
        let entry = groups.entry(key).or_default();
        entry.0.push(finding.advisory.id.clone());
        entry.1.push(finding.advisory.fixed_versions.clone());
    }
    groups
        .into_iter()
        .map(|((ecosystem, name, current), (mut advisories, fixed))| {
            advisories.sort();
            let recommended = minimum_covering_fix(&fixed);
            let manifest_hint = match &recommended {
                Some(version) => manifest_hint(&ecosystem, &name, version),
                None => "tidak ada versi fix yang menutup semua advisory".to_string(),
            };
            FixPlanRow {
                ecosystem,
                name,
                current,
                recommended,
                advisories,
                manifest_hint,
            }
        })
        .collect()
}

fn manifest_hint(ecosystem: &str, name: &str, version: &str) -> String {
    match ecosystem {
        "npm" => format!("npm install {name}@{version}"),
        "PyPI" => format!("pip install {name}=={version}"),
        "Packagist" => format!("composer require {name}:{version}"),
        "Go" => format!("go get {name}@{version}"),
        "Maven" => format!("set {name} to {version}"),
        "crates.io" => format!("cargo add {name}@{version}"),
        _ => format!("upgrade {name} to {version}"),
    }
}

/// Plain-text score explanation from the stored breakdown and default weights.
pub(crate) fn explain_finding(finding: &Finding) -> String {
    let score = config::ScoreSection::default();
    let mut lines = vec![
        format!(
            "{} {}@{}",
            finding.advisory.id, finding.package.name, finding.package.version
        ),
        format!("skor {} ({})", finding.score, finding.tier.label_id()),
        format!(
            "ambang kritis {}, perlu dicek {}",
            score.thresholds.critical, score.thresholds.review
        ),
    ];
    if let Some(item) = &finding.signals.breakdown {
        lines.push(format!("KEV: {} (bobot {})", item.kev, score.weights.kev));
        lines.push(format!(
            "EPSS: {} (bobot {})",
            item.epss, score.weights.epss
        ));
        lines.push(format!(
            "CVSS: {} (bobot {})",
            item.cvss, score.weights.cvss
        ));
        lines.push(format!(
            "direct: {} (bobot {})",
            item.direct, score.weights.direct
        ));
        lines.push(format!(
            "fix: {} (bobot {})",
            item.fix_available, score.weights.fix_available
        ));
        lines.push(format!("total bobot {}", item.total_weight));
    } else {
        lines.push("skor belum dihitung".to_string());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use patchsense_core::model::{
        Advisory, BreakdownSignal, FindingSignals, Package, ReportContext, Summary,
    };

    fn finding(index: u32) -> Finding {
        Finding {
            advisory: Advisory {
                id: format!("GHSA-cap-{index:04}"),
                aliases: vec![format!("CVE-2099-{index:04}")],
                summary: "sample".to_string(),
                severity: Vec::new(),
                database_specific_severity: None,
                references: Vec::new(),
                fixed_versions: vec!["2.0.0".to_string()],
            },
            package: Package {
                ecosystem: Ecosystem::Npm,
                name: "left-pad".to_string(),
                version: "1.0.0".to_string(),
                direct: Some(true),
                dev: false,
                source_file: "package-lock.json".to_string(),
                source_files: Vec::new(),
                line: None,
            },
            tier: Tier::Defer,
            score: 100 - index,
            signals: FindingSignals {
                cves: vec![format!("CVE-2099-{index:04}")],
                breakdown: Some(BreakdownSignal {
                    kev: 0.0,
                    epss: 0.0,
                    cvss: 10.0,
                    direct: 10.0,
                    fix_available: 10.0,
                    total_weight: 100.0,
                }),
                ..FindingSignals::default()
            },
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        let count = findings.len();
        Report {
            schema_version: 1,
            findings,
            warnings: Vec::new(),
            summary: Summary {
                findings: count,
                packages_scanned: 7,
                ..Summary::default()
            },
            ignored: Vec::new(),
            context: ReportContext::default(),
        }
    }

    #[test]
    fn scan_project_output_stops_at_fifty_findings() {
        let findings: Vec<_> = (0..51).map(finding).collect();
        let text = present_scan(&report(findings), 0);
        assert!(text.contains("Menampilkan 50 dari 51 temuan."));
        assert!(text.contains("GHSA-cap-0000"));
        assert!(text.contains("GHSA-cap-0049"));
        assert!(!text.contains("GHSA-cap-0050"));
        assert!(text.contains("\"packages_scanned\": 7"));
        assert!(text.contains("\"schema_version\": 1"));
    }

    #[test]
    fn fix_plan_covers_every_advisory_on_the_package() {
        let mut first = finding(1);
        first.advisory.id = "GHSA-aaaa".to_string();
        first.advisory.fixed_versions = vec!["4.17.21".to_string(), "4.18.0".to_string()];
        first.tier = Tier::Critical;
        let mut second = finding(2);
        second.advisory.id = "GHSA-bbbb".to_string();
        second.advisory.fixed_versions = vec!["4.17.5".to_string()];
        second.tier = Tier::Review;
        let rows = fix_plan(&report(vec![first, second]), None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].recommended.as_deref(), Some("4.17.21"));
        assert_eq!(rows[0].manifest_hint, "npm install left-pad@4.17.21");
        assert_eq!(rows[0].advisories, vec!["GHSA-aaaa", "GHSA-bbbb"]);
        let critical = fix_plan(&report(vec![finding(1)]), Some(Tier::Critical));
        assert!(critical.is_empty());
    }

    #[test]
    fn fix_plan_says_when_no_upgrade_covers_every_advisory() {
        let mut row = finding(1);
        row.advisory.fixed_versions = vec!["not-semver".to_string()];
        let rows = fix_plan(&report(vec![row]), None);
        assert_eq!(rows[0].recommended, None);
        assert_eq!(
            rows[0].manifest_hint,
            "tidak ada versi fix yang menutup semua advisory"
        );
    }

    #[test]
    fn explain_lists_weights_and_thresholds() {
        let text = explain_finding(&finding(3));
        assert!(text.contains("GHSA-cap-0003 left-pad@1.0.0"));
        assert!(text.contains("skor 97"));
        assert!(text.contains("ambang kritis 70"));
        assert!(text.contains("CVSS: 10 (bobot 20)"));
        assert!(text.contains("total bobot 100"));
    }
}
