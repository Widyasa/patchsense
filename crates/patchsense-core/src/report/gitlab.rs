//! GitLab Dependency Scanning report.
//!
//! Schema version is the latest `security-report-schemas` document fetched
//! for this task: 15.2.5.

use serde_json::{json, Value};

use crate::error::CoreError;
use crate::model::{Finding, Report, Tier};

/// `security-report-schemas` dependency-scanning version this renderer emits.
pub const SCHEMA_VERSION: &str = "15.2.5";

/// Pretty GitLab report with a trailing newline.
pub fn render_gitlab(report: &Report) -> Result<String, CoreError> {
    let mut text =
        serde_json::to_string_pretty(&to_value(report)).map_err(|err| CoreError::Json {
            context: "gitlab".to_string(),
            message: err.to_string(),
        })?;
    text.push('\n');
    Ok(text)
}

/// GitLab dependency-scanning document.
pub fn to_value(report: &Report) -> Value {
    let when = gitlab_time(&report.context.generated_at);
    let vulnerabilities: Vec<Value> = report.findings.iter().map(vulnerability).collect();
    json!({
        "version": SCHEMA_VERSION,
        "vulnerabilities": vulnerabilities,
        "scan": {
            "analyzer": tool(),
            "scanner": tool(),
            "type": "dependency_scanning",
            "start_time": when,
            "end_time": when,
            "status": "success"
        }
    })
}

/// GitLab's schema rejects the trailing `Z`.
fn gitlab_time(generated_at: &str) -> String {
    let trimmed = generated_at.trim_end_matches('Z');
    if trimmed.is_empty() {
        "1970-01-01T00:00:00".to_string()
    } else {
        trimmed.to_string()
    }
}

fn tool() -> Value {
    json!({
        "id": "patchsense",
        "name": "PatchSense",
        "version": crate::VERSION,
        "vendor": { "name": "PatchSense" },
        "url": "https://github.com/Widyasa/patchsense"
    })
}

fn vulnerability(finding: &Finding) -> Value {
    let mut identifiers = vec![identifier(&finding.advisory.id)];
    for alias in &finding.advisory.aliases {
        if alias.eq_ignore_ascii_case(&finding.advisory.id) {
            continue;
        }
        identifiers.push(identifier(alias));
    }
    let mut location = json!({
        "file": finding.package.source_file.split(", ").next().unwrap_or(&finding.package.source_file),
        "dependency": {
            "package": { "name": finding.package.name },
            "version": finding.package.version
        }
    });
    if let Some(direct) = finding.package.direct {
        location["dependency"]["direct"] = json!(direct);
    }
    let description = match &finding.import_note {
        Some(note) => format!("{}\n\n{note}", finding.advisory.summary),
        None => finding.advisory.summary.clone(),
    };
    let mut vuln = json!({
        "id": fingerprint(finding),
        "name": finding.advisory.summary,
        "description": description,
        "severity": severity(finding.tier),
        "identifiers": identifiers,
        "location": location
    });
    if !finding.advisory.fixed_versions.is_empty() {
        vuln["solution"] = json!(format!(
            "Upgrade to {}",
            finding.advisory.fixed_versions.join(", ")
        ));
    }
    vuln
}

fn identifier(id: &str) -> Value {
    let kind = if id.starts_with("GHSA-") {
        "ghsa"
    } else if id.len() >= 4 && id[..4].eq_ignore_ascii_case("CVE-") {
        "cve"
    } else {
        "osv"
    };
    let url = if kind == "cve" {
        format!("https://nvd.nist.gov/vuln/detail/{id}")
    } else {
        format!("https://osv.dev/vulnerability/{id}")
    };
    json!({
        "type": kind,
        "name": id,
        "value": id,
        "url": url
    })
}

fn severity(tier: Tier) -> &'static str {
    match tier {
        Tier::Critical => "Critical",
        Tier::Review => "High",
        Tier::Defer => "Low",
    }
}

fn fingerprint(finding: &Finding) -> String {
    format!(
        "{}/{}/{}@{}/{}",
        finding.package.ecosystem.as_osv_str(),
        finding.package.source_file,
        finding.package.name,
        finding.package.version,
        finding.advisory.id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Advisory, Ecosystem, Finding, FindingSignals, Package, Report, ReportContext, Summary,
    };

    #[test]
    fn gitlab_report_matches_schema_15_2_5() {
        let report = Report {
            schema_version: 1,
            findings: vec![Finding {
                advisory: Advisory {
                    id: "GHSA-35jh-r3h4-6jhm".to_string(),
                    aliases: vec!["CVE-2021-23337".to_string()],
                    summary: "Command Injection in lodash".to_string(),
                    severity: Vec::new(),
                    database_specific_severity: None,
                    references: Vec::new(),
                    fixed_versions: vec!["4.17.21".to_string()],
                    imports: Vec::new(),
                },
                package: Package {
                    ecosystem: Ecosystem::Npm,
                    name: "lodash".to_string(),
                    version: "4.17.15".to_string(),
                    direct: Some(true),
                    dev: false,
                    source_file: "package-lock.json".to_string(),
                    source_files: Vec::new(),
                    line: None,
                },
                tier: Tier::Defer,
                score: 37,
                signals: FindingSignals::default(),
                import_note: None,
            }],
            warnings: Vec::new(),
            summary: Summary {
                packages_scanned: 1,
                findings: 1,
                critical: 0,
                review: 0,
                defer: 1,
                max_score: 37,
                failed: false,
            },
            ignored: Vec::new(),
            context: ReportContext {
                generated_at: "2026-10-25T08:00:00Z".to_string(),
                ..ReportContext::default()
            },
        };
        let value = to_value(&report);
        assert_eq!(value["version"], SCHEMA_VERSION);
        assert_eq!(value["vulnerabilities"][0]["severity"], "Low");
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../tests/schemas/dependency-scanning-report-format-15.2.5.json"
        ))
        .expect("gitlab schema");
        let validator = jsonschema::draft7::options()
            .build(&schema)
            .expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|err| err.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        let mut snapshot = value;
        snapshot["scan"]["start_time"] = Value::String("<redacted>".to_string());
        snapshot["scan"]["end_time"] = Value::String("<redacted>".to_string());
        insta::assert_json_snapshot!(snapshot);
    }
}
