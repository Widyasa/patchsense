//! Pull-request and merge-request comments.
//!
//! GitHub is implemented here. GitLab notes land in the next task.

mod github;
mod gitlab;

use std::process::ExitCode;

use anyhow::Context;
use serde_json::Value;

use patchsense::http::ReqwestClient;
use patchsense::model::{
    Advisory, BreakdownSignal, Ecosystem, Finding, FindingSignals, Package, Report, ReportContext,
    Summary, Tier,
};
use patchsense::report::markdown::{render_markdown, MARKER};

use crate::cli::CommentArgs;

/// What an upsert did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentOutcome {
    /// A new comment was created.
    Created(u64),
    /// An existing marker comment was edited.
    Updated(u64),
    /// The API refused the write. Fork pull requests often do this.
    Forbidden,
}

/// Run `patchsense comment`.
pub async fn run(args: CommentArgs) -> anyhow::Result<ExitCode> {
    let report = load_report(&args.report)?;
    let top = args.top.unwrap_or(20);
    let markdown = render_markdown(&report, top);
    if args.dry_run {
        print!("{markdown}");
        return Ok(ExitCode::SUCCESS);
    }
    match provider(&args.provider)? {
        Provider::Github => {
            let target = github::target_from_env()?;
            let client = ReqwestClient::with_bearer(&target.token)
                .context("failed to build the GitHub HTTP client")?;
            match github::upsert(&client, &target, &markdown).await? {
                CommentOutcome::Created(id) => println!("created GitHub comment {id}"),
                CommentOutcome::Updated(id) => println!("updated GitHub comment {id}"),
                CommentOutcome::Forbidden => {
                    eprintln!(
                        "warning: GitHub returned HTTP 403, so the comment was not written. Fork pull requests often have a read-only token."
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Provider::Gitlab => {
            let target = gitlab::target_from_env()?;
            let client = ReqwestClient::with_private_token(&target.token)
                .context("failed to build the GitLab HTTP client")?;
            match gitlab::upsert(&client, &target, &markdown).await? {
                CommentOutcome::Created(id) => println!("created GitLab note {id}"),
                CommentOutcome::Updated(id) => println!("updated GitLab note {id}"),
                CommentOutcome::Forbidden => {
                    eprintln!("warning: GitLab returned HTTP 403, so the note was not written.");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

enum Provider {
    Github,
    Gitlab,
}

fn provider(flag: &str) -> anyhow::Result<Provider> {
    match flag {
        "github" => Ok(Provider::Github),
        "gitlab" => Ok(Provider::Gitlab),
        "auto" => {
            if std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
                Ok(Provider::Github)
            } else if std::env::var("GITLAB_CI").ok().as_deref() == Some("true") {
                Ok(Provider::Gitlab)
            } else {
                anyhow::bail!(
                    "could not detect a comment provider; set --provider github or --provider gitlab"
                )
            }
        }
        other => anyhow::bail!("unknown comment provider `{other}`"),
    }
}

fn load_report(path: &std::path::Path) -> anyhow::Result<Report> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    parse_rendered_report(&text).with_context(|| format!("failed to parse {}", path.display()))
}

/// Rebuild a [`Report`] from the JSON document `scan --format json` writes.
pub fn parse_rendered_report(text: &str) -> anyhow::Result<Report> {
    let value: Value = serde_json::from_str(text).context("report is not JSON")?;
    let summary = &value["summary"];
    let findings = value["findings"]
        .as_array()
        .context("report is missing findings")?;
    let mut report = Report {
        schema_version: value["schema_version"].as_u64().unwrap_or(1) as u32,
        findings: Vec::new(),
        warnings: strings(&value["warnings"]),
        summary: Summary {
            packages_scanned: summary["packages_scanned"].as_u64().unwrap_or(0) as usize,
            findings: summary["findings"].as_u64().unwrap_or(0) as usize,
            critical: summary["by_tier"]["critical"].as_u64().unwrap_or(0) as usize,
            review: summary["by_tier"]["review"].as_u64().unwrap_or(0) as usize,
            defer: summary["by_tier"]["defer"].as_u64().unwrap_or(0) as usize,
            max_score: summary["max_score"].as_u64().unwrap_or(0) as u32,
            failed: summary["failed"].as_bool().unwrap_or(false),
        },
        ignored: Vec::new(),
        context: ReportContext::default(),
    };
    for item in findings {
        report.findings.push(finding_from_json(item)?);
    }
    Ok(report)
}

fn finding_from_json(item: &Value) -> anyhow::Result<Finding> {
    let id = item["id"]
        .as_str()
        .context("finding is missing id")?
        .to_string();
    let ecosystem_name = item["package"]["ecosystem"]
        .as_str()
        .context("finding is missing package.ecosystem")?;
    let ecosystem = Ecosystem::parse_config_name(ecosystem_name)?;
    let tier = match item["tier"].as_str().unwrap_or("defer") {
        "critical" => Tier::Critical,
        "review" => Tier::Review,
        _ => Tier::Defer,
    };
    let breakdown = item.get("score_breakdown").and_then(|value| {
        if value.is_null() {
            None
        } else {
            Some(BreakdownSignal {
                kev: value["kev"].as_f64().unwrap_or(0.0),
                epss: value["epss"].as_f64().unwrap_or(0.0),
                cvss: value["cvss"].as_f64().unwrap_or(0.0),
                direct: value["direct"].as_f64().unwrap_or(0.0),
                fix_available: value["fix_available"].as_f64().unwrap_or(0.0),
                total_weight: value["total_weight"].as_f64().unwrap_or(100.0),
            })
        }
    });
    Ok(Finding {
        advisory: Advisory {
            id,
            aliases: strings(&item["aliases"]),
            summary: item["summary"].as_str().unwrap_or("").to_string(),
            severity: Vec::new(),
            database_specific_severity: None,
            references: strings(&item["references"]),
            fixed_versions: strings(&item["fixed_versions"]),
            imports: Vec::new(),
        },
        package: Package {
            ecosystem,
            name: item["package"]["name"].as_str().unwrap_or("").to_string(),
            version: item["package"]["version"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            direct: item["package"]["direct"].as_bool(),
            dev: item["package"]["dev"].as_bool().unwrap_or(false),
            source_file: item["source_file"].as_str().unwrap_or("").to_string(),
            source_files: Vec::new(),
            line: None,
        },
        tier,
        score: item["score"].as_u64().unwrap_or(0) as u32,
        signals: FindingSignals {
            cves: strings(&item["cves"]),
            breakdown,
            ..FindingSignals::default()
        },
        import_note: item["import_note"].as_str().map(str::to_string),
    })
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// True when a comment body is one PatchSense already owns.
pub fn contains_marker(body: &str) -> bool {
    body.contains(MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_cache_warning_is_in_the_comment() {
        let report = parse_rendered_report(
            r#"{"schema_version":1,"summary":{"packages_scanned":1,"findings":1,"by_tier":{"critical":1,"review":0,"defer":0},"max_score":100,"failed":true},"warnings":["offline: cached EPSS for CVE-2021-23337 is 2h old, past the 1h TTL; using the stale score"],"findings":[{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","package":{"ecosystem":"npm","name":"lodash","version":"4.17.14"},"score":100,"tier":"critical"}]}"#,
        )
        .expect("parse");
        let markdown = render_markdown(&report, 20);
        assert!(markdown.contains("## Warnings"), "{markdown}");
        assert!(
            markdown.contains("cached EPSS for CVE-2021-23337 is 2h old"),
            "{markdown}"
        );
    }

    #[test]
    fn empty_rendered_report_becomes_the_empty_comment() {
        let report = parse_rendered_report(
            r#"{"schema_version":1,"summary":{"packages_scanned":0,"findings":0,"by_tier":{"critical":0,"review":0,"defer":0},"max_score":0,"failed":false},"findings":[]}"#,
        )
        .expect("parse");
        let markdown = render_markdown(&report, 20);
        assert!(markdown.contains(MARKER));
        assert!(markdown.contains("No vulnerabilities"));
    }

    #[test]
    fn rendered_finding_keeps_the_package_and_score() {
        let report = parse_rendered_report(
            r#"{"schema_version":1,"summary":{"findings":1,"by_tier":{"critical":0,"review":0,"defer":1},"max_score":37},"findings":[{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"summary":"Command Injection in lodash","package":{"ecosystem":"npm","name":"lodash","version":"4.17.14"},"score":37,"tier":"defer","score_breakdown":{"kev":0,"epss":3.075,"cvss":14.4,"direct":10,"fix_available":10,"total_weight":100},"references":["https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"]}]}"#,
        )
        .expect("parse");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].package.name, "lodash");
        assert_eq!(report.findings[0].score, 37);
        let markdown = render_markdown(&report, 20);
        assert!(markdown.contains("GHSA-35jh-r3h4-6jhm"));
        assert!(markdown.contains("lodash"));
        assert!(!markdown.contains("imported package not seen"));
    }

    #[test]
    fn an_import_note_is_copied_into_the_comment() {
        let report = parse_rendered_report(
            r#"{"schema_version":1,"summary":{"findings":1,"by_tier":{"critical":0,"review":0,"defer":1},"max_score":20},"findings":[{"id":"GO-2026-5932","summary":"openpgp","package":{"ecosystem":"Go","name":"golang.org/x/crypto","version":"v0.31.0"},"score":20,"tier":"defer","import_note":"imported package not seen"}]}"#,
        )
        .expect("parse");
        assert_eq!(
            report.findings[0].import_note.as_deref(),
            Some("imported package not seen")
        );
        assert_eq!(report.findings[0].score, 20);
        let markdown = render_markdown(&report, 20);
        assert!(markdown.contains("GO-2026-5932 (imported package not seen)"));
    }
}
