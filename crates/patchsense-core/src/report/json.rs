//! JSON report for PRD §8 (`schema_version` 1).

use serde::Serialize;
use serde_json::Value;

use crate::error::CoreError;
use crate::model::{Finding, Report, Tier};

/// Serialize `report` as pretty JSON with a trailing newline.
pub fn render_json(report: &Report) -> Result<String, CoreError> {
    let value = to_value(report);
    let mut text = serde_json::to_string_pretty(&value).map_err(|err| CoreError::Json {
        context: "report".to_string(),
        message: err.to_string(),
    })?;
    text.push('\n');
    Ok(text)
}

/// JSON value for `report`. Timestamps are left as stored on the report.
pub fn to_value(report: &Report) -> Value {
    serde_json::to_value(JsonReport::from_report(report)).expect("report JSON is a map")
}

#[derive(Serialize)]
struct JsonReport {
    schema_version: u32,
    tool: ToolJson,
    generated_at: String,
    target: String,
    lockfiles: Vec<LockfileJson>,
    data_sources: DataSourcesJson,
    config: ConfigJson,
    summary: SummaryJson,
    findings: Vec<FindingJson>,
    ignored: Vec<IgnoredJson>,
    explain: ExplainJson,
    warnings: Vec<String>,
}

impl JsonReport {
    fn from_report(report: &Report) -> Self {
        let context = &report.context;
        Self {
            schema_version: report.schema_version,
            tool: ToolJson {
                name: "patchsense".to_string(),
                version: crate::VERSION.to_string(),
            },
            generated_at: context.generated_at.clone(),
            target: context.target.clone(),
            lockfiles: context
                .lockfiles
                .iter()
                .map(|file| LockfileJson {
                    path: file.path.clone(),
                    ecosystem: file.ecosystem.clone(),
                    packages: file.packages,
                    status: file.status.clone(),
                    warnings: file.warnings.clone(),
                })
                .collect(),
            data_sources: DataSourcesJson {
                osv: FetchJson {
                    fetched_at: context.osv_fetched_at.clone(),
                    from_cache: context.osv_from_cache,
                },
                epss: EpssSourceJson {
                    date: context.epss_date.clone(),
                    from_cache: context.epss_from_cache,
                },
                kev: KevSourceJson {
                    catalog_version: context.kev_catalog_version.clone(),
                    from_cache: context.kev_from_cache,
                },
            },
            config: ConfigJson {
                weights: WeightsJson {
                    kev: context.weights.kev,
                    epss: context.weights.epss,
                    cvss: context.weights.cvss,
                    direct: context.weights.direct,
                    fix_available: context.weights.fix_available,
                },
                thresholds: ThresholdsJson {
                    critical: context.threshold_critical,
                    review: context.threshold_review,
                },
                fail_on: context.fail_on.clone(),
            },
            summary: SummaryJson {
                packages_scanned: report.summary.packages_scanned,
                findings: report.summary.findings,
                by_tier: ByTierJson {
                    critical: report.summary.critical,
                    review: report.summary.review,
                    defer: report.summary.defer,
                },
                max_score: report.summary.max_score,
                failed: report.summary.failed,
            },
            findings: report
                .findings
                .iter()
                .map(FindingJson::from_finding)
                .collect(),
            ignored: report
                .ignored
                .iter()
                .map(|item| IgnoredJson {
                    id: item.id.clone(),
                    package: item.package.clone(),
                    reason: item.reason.clone(),
                    expires: item.expires.clone(),
                })
                .collect(),
            explain: ExplainJson {
                agent: context.explain_agent.clone(),
                status: context.explain_status.clone(),
            },
            warnings: report.warnings.clone(),
        }
    }
}

#[derive(Serialize)]
struct ToolJson {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct LockfileJson {
    path: String,
    ecosystem: String,
    packages: usize,
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct DataSourcesJson {
    osv: FetchJson,
    epss: EpssSourceJson,
    kev: KevSourceJson,
}

#[derive(Serialize)]
struct FetchJson {
    fetched_at: String,
    from_cache: bool,
}

#[derive(Serialize)]
struct EpssSourceJson {
    date: Option<String>,
    from_cache: bool,
}

#[derive(Serialize)]
struct KevSourceJson {
    catalog_version: Option<String>,
    from_cache: bool,
}

#[derive(Serialize)]
struct ConfigJson {
    weights: WeightsJson,
    thresholds: ThresholdsJson,
    fail_on: String,
}

#[derive(Serialize)]
struct WeightsJson {
    kev: f64,
    epss: f64,
    cvss: f64,
    direct: f64,
    fix_available: f64,
}

#[derive(Serialize)]
struct ThresholdsJson {
    critical: f64,
    review: f64,
}

#[derive(Serialize)]
struct SummaryJson {
    packages_scanned: usize,
    findings: usize,
    by_tier: ByTierJson,
    max_score: u32,
    failed: bool,
}

#[derive(Serialize)]
struct ByTierJson {
    critical: usize,
    review: usize,
    defer: usize,
}

#[derive(Serialize)]
struct FindingJson {
    id: String,
    aliases: Vec<String>,
    cves: Vec<String>,
    summary: String,
    package: PackageJson,
    source_file: String,
    fixed_versions: Vec<String>,
    cvss: Option<CvssJson>,
    epss: Option<EpssJson>,
    kev: Option<KevJson>,
    score: u32,
    tier: &'static str,
    tier_label: &'static str,
    score_breakdown: BreakdownJson,
    references: Vec<String>,
    ignored: bool,
    explanation: Option<ExplanationJson>,
}

impl FindingJson {
    fn from_finding(finding: &Finding) -> Self {
        let signals = &finding.signals;
        let cves = if signals.cves.is_empty() {
            finding
                .advisory
                .aliases
                .iter()
                .filter(|id| id.len() >= 4 && id[..4].eq_ignore_ascii_case("CVE-"))
                .map(|id| id.to_ascii_uppercase())
                .collect()
        } else {
            signals.cves.clone()
        };
        let breakdown = signals
            .breakdown
            .clone()
            .unwrap_or(crate::model::BreakdownSignal {
                kev: 0.0,
                epss: 0.0,
                cvss: 0.0,
                direct: 0.0,
                fix_available: 0.0,
                total_weight: 100.0,
            });
        let references =
            with_official_links(&finding.advisory.references, &finding.advisory.id, &cves);
        Self {
            id: finding.advisory.id.clone(),
            aliases: finding.advisory.aliases.clone(),
            cves,
            summary: finding.advisory.summary.clone(),
            package: PackageJson {
                ecosystem: finding.package.ecosystem.as_osv_str().to_string(),
                name: finding.package.name.clone(),
                version: finding.package.version.clone(),
                direct: finding.package.direct,
                dev: finding.package.dev,
            },
            source_file: finding.package.source_file.clone(),
            fixed_versions: finding.advisory.fixed_versions.clone(),
            cvss: signals.cvss.as_ref().map(|cvss| CvssJson {
                version: cvss.version.clone(),
                vector: cvss.vector.clone(),
                base_score: cvss.base_score,
                source: cvss.source.clone(),
            }),
            epss: signals.epss.as_ref().map(|epss| EpssJson {
                score: epss.score,
                percentile: epss.percentile,
                date: epss.date.clone(),
            }),
            kev: signals.kev.as_ref().map(|kev| KevJson {
                date_added: kev.date_added.clone(),
                due_date: kev.due_date.clone(),
                ransomware: kev.ransomware.clone(),
                name: kev.name.clone(),
            }),
            score: finding.score,
            tier: tier_token(finding.tier),
            tier_label: finding.tier.label_id(),
            score_breakdown: BreakdownJson {
                kev: json_number(breakdown.kev),
                epss: json_number(breakdown.epss),
                cvss: json_number(breakdown.cvss),
                direct: json_number(breakdown.direct),
                fix_available: json_number(breakdown.fix_available),
                total_weight: json_number(breakdown.total_weight),
            },
            references,
            ignored: false,
            explanation: signals.explanation.as_ref().map(|item| ExplanationJson {
                agent: item.agent.clone(),
                text: item.text.clone(),
                disclaimer: item.disclaimer.clone(),
            }),
        }
    }
}

/// Four decimal places. Binary fractions such as `7.2 * 2` print as `14.4`.
fn json_number(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn tier_token(tier: Tier) -> &'static str {
    match tier {
        Tier::Critical => "critical",
        Tier::Review => "review",
        Tier::Defer => "defer",
    }
}

fn with_official_links(existing: &[String], id: &str, cves: &[String]) -> Vec<String> {
    let mut urls = existing.to_vec();
    let osv = format!("https://osv.dev/vulnerability/{id}");
    if !urls.iter().any(|url| url == &osv) {
        urls.insert(0, osv);
    }
    for cve in cves {
        let nvd = format!("https://nvd.nist.gov/vuln/detail/{cve}");
        if !urls.iter().any(|url| url == &nvd) {
            urls.push(nvd);
        }
    }
    urls
}

#[derive(Serialize)]
struct PackageJson {
    ecosystem: String,
    name: String,
    version: String,
    direct: Option<bool>,
    dev: bool,
}

#[derive(Serialize)]
struct CvssJson {
    version: Option<String>,
    vector: Option<String>,
    base_score: f64,
    source: String,
}

#[derive(Serialize)]
struct EpssJson {
    score: f64,
    percentile: f64,
    date: String,
}

#[derive(Serialize)]
struct KevJson {
    date_added: String,
    due_date: String,
    ransomware: String,
    name: String,
}

#[derive(Serialize)]
struct BreakdownJson {
    kev: f64,
    epss: f64,
    cvss: f64,
    direct: f64,
    fix_available: f64,
    total_weight: f64,
}

#[derive(Serialize)]
struct ExplanationJson {
    agent: String,
    text: String,
    disclaimer: String,
}

#[derive(Serialize)]
struct IgnoredJson {
    id: String,
    package: String,
    reason: String,
    expires: Option<String>,
}

#[derive(Serialize)]
struct ExplainJson {
    agent: Option<String>,
    status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScoreSection;
    use crate::model::{
        Advisory, BreakdownSignal, CvssSignal, Ecosystem, EpssSignal, Finding, FindingSignals,
        IgnoredItem, LockfileRecord, Package, Report, ReportContext, Severity, Summary, Tier,
    };
    use crate::score::{score_request, EpssSample, ScoreRequest};

    fn case_b_report() -> Report {
        let request = ScoreRequest {
            package_name: "lodash".to_string(),
            kev: false,
            epss: Some(EpssSample {
                score: 0.0123,
                percentile: 0.78,
            }),
            cvss_base: Some(7.2),
            direct: Some(true),
            fix_available: true,
        };
        let score = ScoreSection::default();
        let (scored, warnings) = score_request(&request, &score);
        let breakdown = &scored.breakdown;
        Report {
            schema_version: 1,
            findings: vec![Finding {
                advisory: Advisory {
                    id: "GHSA-35jh-r3h4-6jhm".to_string(),
                    aliases: vec!["CVE-2021-23337".to_string()],
                    summary: "Command Injection in lodash".to_string(),
                    severity: vec![Severity {
                        kind: "CVSS_V3".to_string(),
                        score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H".to_string(),
                    }],
                    database_specific_severity: None,
                    references: vec![
                        "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm".to_string()
                    ],
                    fixed_versions: vec!["4.17.21".to_string()],
                },
                package: Package {
                    ecosystem: Ecosystem::Npm,
                    name: "lodash".to_string(),
                    version: "4.17.15".to_string(),
                    direct: Some(true),
                    dev: false,
                    source_file: "package-lock.json".to_string(),
                    source_files: vec!["package-lock.json".to_string()],
                    line: Some(12),
                },
                tier: scored.tier,
                score: scored.score,
                signals: FindingSignals {
                    cves: vec!["CVE-2021-23337".to_string()],
                    cvss: Some(CvssSignal {
                        version: Some("3.1".to_string()),
                        vector: Some("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H".to_string()),
                        base_score: 7.2,
                        source: "osv".to_string(),
                    }),
                    epss: Some(EpssSignal {
                        score: 0.0123,
                        percentile: 0.78,
                        date: "2026-10-24".to_string(),
                    }),
                    kev: None,
                    breakdown: Some(BreakdownSignal {
                        kev: breakdown.kev,
                        epss: breakdown.epss,
                        cvss: breakdown.cvss,
                        direct: breakdown.direct,
                        fix_available: breakdown.fix_available,
                        total_weight: breakdown.total_weight,
                    }),
                    explanation: None,
                },
            }],
            warnings,
            summary: Summary {
                packages_scanned: 2,
                findings: 1,
                critical: 0,
                review: 0,
                defer: usize::from(scored.tier == Tier::Defer),
                max_score: scored.score,
                failed: false,
            },
            ignored: vec![IgnoredItem {
                id: "GHSA-xxxx-xxxx-xxxx".to_string(),
                package: "minimist@1.2.5".to_string(),
                reason: "Hanya di script build".to_string(),
                expires: Some("2027-01-31".to_string()),
            }],
            context: ReportContext {
                target: ".".to_string(),
                generated_at: "2026-10-25T08:00:00Z".to_string(),
                lockfiles: vec![LockfileRecord {
                    path: "package-lock.json".to_string(),
                    ecosystem: "npm".to_string(),
                    packages: 2,
                    status: "ok".to_string(),
                    warnings: Vec::new(),
                }],
                osv_fetched_at: "2026-10-25T08:00:01Z".to_string(),
                osv_from_cache: false,
                epss_date: Some("2026-10-24".to_string()),
                epss_from_cache: true,
                kev_catalog_version: Some("2026.10.23".to_string()),
                kev_from_cache: true,
                explain_status: "not_requested".to_string(),
                ..ReportContext::default()
            },
        }
    }

    #[test]
    fn case_b_json_matches_the_schema_and_snapshot() {
        let report = case_b_report();
        assert_eq!(report.findings[0].score, 37);
        assert_eq!(report.findings[0].tier, Tier::Defer);
        let mut value = to_value(&report);
        let schema: Value =
            serde_json::from_str(include_str!("../../../../schemas/report.v1.json"))
                .expect("schema JSON");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|err| err.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}");

        value["generated_at"] = Value::String("<redacted>".to_string());
        value["data_sources"]["osv"]["fetched_at"] = Value::String("<redacted>".to_string());
        insta::assert_json_snapshot!(value);
    }
}
