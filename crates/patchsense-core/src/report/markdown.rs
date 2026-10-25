//! Markdown comment body. The hidden marker is how PR comments are updated.

use crate::model::{Finding, Report};

/// Marker that `patchsense comment` searches for.
pub const MARKER: &str = "<!-- patchsense-report -->";

/// Empty-report sentence required by the spec.
pub const EMPTY: &str = "Tidak ada kerentanan";

/// Render a comment. `top` limits the table and the folded details.
pub fn render_markdown(report: &Report, top: usize) -> String {
    if report.findings.is_empty() {
        return format!("{MARKER}\n{EMPTY}\n");
    }
    let shown: Vec<&Finding> = report.findings.iter().take(top).collect();
    let mut out = String::new();
    out.push_str(MARKER);
    out.push_str("\n\n## Ringkasan\n\n");
    out.push_str(&format!(
        "| Tingkat | Jumlah |\n| --- | ---: |\n| Kritis | {} |\n| Perlu dicek | {} |\n| Bisa ditunda | {} |\n\n",
        report.summary.critical, report.summary.review, report.summary.defer
    ));
    out.push_str("## Temuan\n\n");
    out.push_str(
        "| Skor | Tingkat | Paket | Versi | Advisory |\n| ---: | --- | --- | --- | --- |\n",
    );
    for finding in &shown {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            finding.score,
            finding.tier.label_id(),
            finding.package.name,
            finding.package.version,
            finding.advisory.id
        ));
    }
    out.push('\n');
    for finding in &shown {
        out.push_str(&detail(finding));
    }
    out
}

fn detail(finding: &Finding) -> String {
    let breakdown = finding
        .signals
        .breakdown
        .as_ref()
        .map(|item| {
            format!(
                "- KEV: {kev}\n- EPSS: {epss}\n- CVSS: {cvss}\n- direct: {direct}\n- fix: {fix}\n",
                kev = item.kev,
                epss = item.epss,
                cvss = item.cvss,
                direct = item.direct,
                fix = item.fix_available
            )
        })
        .unwrap_or_else(|| "- skor: belum dihitung\n".to_string());
    let mut links = finding.advisory.references.clone();
    if links.is_empty() {
        links.push(format!(
            "https://osv.dev/vulnerability/{}",
            finding.advisory.id
        ));
    }
    let mut link_lines = String::new();
    for link in links {
        link_lines.push_str(&format!("- {link}\n"));
    }
    let explanation = finding
        .signals
        .explanation
        .as_ref()
        .map(|item| format!("\n**{}:** {}\n", item.disclaimer, item.text))
        .unwrap_or_default();
    format!(
        "<details>\n<summary>{id} {name}@{version} — skor {score} ({tier})</summary>\n\n{summary}\n\n{breakdown}\n{links}{explanation}</details>\n\n",
        id = finding.advisory.id,
        name = finding.package.name,
        version = finding.package.version,
        score = finding.score,
        tier = finding.tier.label_id(),
        summary = finding.advisory.summary,
        links = link_lines
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Advisory, BreakdownSignal, Ecosystem, Finding, FindingSignals, Package, Report,
        ReportContext, Summary, Tier,
    };

    fn finding() -> Finding {
        Finding {
            advisory: Advisory {
                id: "GHSA-35jh-r3h4-6jhm".to_string(),
                aliases: vec!["CVE-2021-23337".to_string()],
                summary: "Command Injection in lodash".to_string(),
                severity: Vec::new(),
                database_specific_severity: None,
                references: vec!["https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm".to_string()],
                fixed_versions: vec!["4.17.21".to_string()],
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
            signals: FindingSignals {
                cves: vec!["CVE-2021-23337".to_string()],
                breakdown: Some(BreakdownSignal {
                    kev: 0.0,
                    epss: 3.075,
                    cvss: 14.4,
                    direct: 10.0,
                    fix_available: 10.0,
                    total_weight: 100.0,
                }),
                ..FindingSignals::default()
            },
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: 1,
            summary: Summary {
                packages_scanned: 1,
                findings: findings.len(),
                critical: 0,
                review: 0,
                defer: findings.len(),
                max_score: findings.first().map(|item| item.score).unwrap_or(0),
                failed: false,
            },
            findings,
            warnings: Vec::new(),
            ignored: Vec::new(),
            context: ReportContext::default(),
        }
    }

    #[test]
    fn finding_and_empty_markdown_match_snapshots() {
        let filled = render_markdown(&report(vec![finding()]), 20);
        assert!(filled.starts_with(MARKER));
        insta::assert_snapshot!("with_finding", filled);
        let empty = render_markdown(&report(Vec::new()), 20);
        assert!(empty.contains(EMPTY));
        insta::assert_snapshot!("empty", empty);
    }

    #[test]
    fn explanation_is_labeled_as_possibly_wrong() {
        use crate::model::Explanation;
        let mut item = finding();
        item.signals.explanation = Some(Explanation {
            agent: "codex".to_string(),
            text: "Upgrade lodash to 4.17.21.".to_string(),
            disclaimer: "Penjelasan AI, bisa keliru".to_string(),
        });
        let text = render_markdown(&report(vec![item]), 20);
        assert!(text.contains("**Penjelasan AI, bisa keliru:** Upgrade lodash to 4.17.21."));
    }
}
