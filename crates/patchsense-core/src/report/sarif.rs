//! SARIF 2.1.0. One rule per advisory id, one result per finding.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::error::CoreError;
use crate::model::{Finding, Report, Tier};

/// Pretty SARIF document with a trailing newline.
pub fn render_sarif(report: &Report) -> Result<String, CoreError> {
    let mut text =
        serde_json::to_string_pretty(&to_value(report)).map_err(|err| CoreError::Json {
            context: "sarif".to_string(),
            message: err.to_string(),
        })?;
    text.push('\n');
    Ok(text)
}

/// SARIF 2.1.0 value for `report`.
pub fn to_value(report: &Report) -> Value {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    for finding in &report.findings {
        let id = finding.advisory.id.as_str();
        let severity = format!("{:.1}", f64::from(finding.score) / 10.0);
        let entry = rules.entry(id).or_insert_with(|| rule(finding, &severity));
        if let Some(props) = entry.get_mut("properties") {
            let current = props
                .get("security-severity")
                .and_then(Value::as_str)
                .and_then(|text| text.parse::<f64>().ok())
                .unwrap_or(0.0);
            if f64::from(finding.score) / 10.0 > current {
                props["security-severity"] = json!(severity);
            }
        }
    }
    let rule_list: Vec<Value> = rules.into_values().collect();
    let results: Vec<Value> = report.findings.iter().map(result).collect();
    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "patchsense",
                    "version": crate::VERSION,
                    "informationUri": "https://github.com/Widyasa/patchsense",
                    "rules": rule_list
                }
            },
            "results": results
        }]
    })
}

fn rule(finding: &Finding, severity: &str) -> Value {
    json!({
        "id": finding.advisory.id,
        "shortDescription": { "text": finding.advisory.summary },
        "help": { "text": finding.advisory.summary },
        "properties": { "security-severity": severity }
    })
}

fn result(finding: &Finding) -> Value {
    let path = finding
        .package
        .source_file
        .split(", ")
        .next()
        .unwrap_or(finding.package.source_file.as_str());
    let line = finding.package.line.unwrap_or(1).max(1);
    let mut text = format!(
        "{}@{}: {} (score {})",
        finding.package.name, finding.package.version, finding.advisory.summary, finding.score
    );
    if let Some(note) = &finding.import_note {
        text.push(' ');
        text.push_str(note);
    }
    json!({
        "ruleId": finding.advisory.id,
        "level": level(finding.tier),
        "message": {
            "text": text
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": path },
                "region": { "startLine": line }
            }
        }],
        "partialFingerprints": {
            "patchsense/v1": fingerprint(finding)
        }
    })
}

fn level(tier: Tier) -> &'static str {
    match tier {
        Tier::Critical => "error",
        Tier::Review => "warning",
        Tier::Defer => "note",
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

    fn finding(id: &str, score: u32, tier: Tier, line: Option<u32>) -> Finding {
        Finding {
            advisory: Advisory {
                id: id.to_string(),
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
                line,
            },
            tier,
            score,
            signals: FindingSignals::default(),
            import_note: None,
        }
    }

    #[test]
    fn sarif_snapshot_matches_the_schema() {
        let report = Report {
            schema_version: 1,
            findings: vec![
                finding("GHSA-35jh-r3h4-6jhm", 37, Tier::Defer, None),
                finding("GHSA-aaaa-bbbb-cccc", 80, Tier::Critical, Some(12)),
            ],
            warnings: Vec::new(),
            summary: Summary {
                packages_scanned: 2,
                findings: 2,
                critical: 1,
                review: 0,
                defer: 1,
                max_score: 80,
                failed: true,
            },
            ignored: Vec::new(),
            context: ReportContext::default(),
        };
        let value = to_value(&report);
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"][0]["level"], "note");
        assert_eq!(value["runs"][0]["results"][1]["level"], "error");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            1
        );
        assert_eq!(
            value["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            12
        );
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"][1]["properties"]["security-severity"],
            "8.0"
        );

        let schema: Value = serde_json::from_str(include_str!(
            "../../../../tests/schemas/sarif-schema-2.1.0.json"
        ))
        .expect("sarif schema");
        let validator = jsonschema::draft4::options()
            .build(&schema)
            .expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|err| err.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        insta::assert_json_snapshot!(value);
    }
}
