//! Colorless and colored scan tables (PRD AC6.1).

use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};

use patchsense_core::model::{Finding, Report, Tier};

/// Render findings at or above `min_score`. The footer counts only those rows.
///
/// `color` paints the tier cell. Callers pass false for a non-TTY, `--no-color`,
/// or `NO_COLOR`. The table itself is forced out of comfy-table's TTY mode so
/// the width does not depend on the terminal.
pub fn render_table(report: &Report, color: bool, min_score: u32) -> String {
    let shown: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|finding| finding.score >= min_score)
        .collect();
    let mut table = Table::new();
    table
        .load_style(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Disabled)
        .force_no_tty()
        .set_header([
            "Score",
            "Tier",
            "Package",
            "Version",
            "Advisory/CVE",
            "KEV",
            "EPSS",
            "CVSS",
            "Fix",
        ]);
    if color {
        table.enforce_styling();
    }
    for finding in &shown {
        table.add_row(row(finding, color));
    }
    let critical = shown
        .iter()
        .filter(|finding| finding.tier == Tier::Critical)
        .count();
    let review = shown
        .iter()
        .filter(|finding| finding.tier == Tier::Review)
        .count();
    let defer = shown
        .iter()
        .filter(|finding| finding.tier == Tier::Defer)
        .count();
    let mut text = format!("{table}\nCritical: {critical}  Review: {review}  Defer: {defer}\n");
    if let Some(explanation) = shown
        .iter()
        .find_map(|finding| finding.signals.explanation.as_ref())
    {
        text.push_str(&format!(
            "{}: {}\n",
            explanation.disclaimer, explanation.text
        ));
    }
    text
}

fn row(finding: &Finding, color: bool) -> Vec<Cell> {
    let tier = Cell::new(finding.tier.label());
    let tier = if color {
        tier.fg(tier_color(finding.tier))
    } else {
        tier
    };
    vec![
        Cell::new(finding.score.to_string()),
        tier,
        Cell::new(&finding.package.name),
        Cell::new(&finding.package.version),
        Cell::new(advisory_label(finding)),
        Cell::new(if finding.signals.kev.is_some() {
            "yes"
        } else {
            "no"
        }),
        Cell::new(match &finding.signals.epss {
            Some(epss) => format!("{:.4}", epss.score),
            None => "-".to_string(),
        }),
        Cell::new(match &finding.signals.cvss {
            Some(cvss) => format!("{}", cvss.base_score),
            None => "-".to_string(),
        }),
        Cell::new(if finding.advisory.fixed_versions.is_empty() {
            "-".to_string()
        } else {
            finding.advisory.fixed_versions.join(", ")
        }),
    ]
}

fn advisory_label(finding: &Finding) -> String {
    let label = match finding.signals.cves.first() {
        Some(cve) => format!("{} ({cve})", finding.advisory.id),
        None => finding.advisory.id.clone(),
    };
    match &finding.import_note {
        Some(note) => format!("{label} ({note})"),
        None => label,
    }
}

fn tier_color(tier: Tier) -> Color {
    match tier {
        Tier::Critical => Color::Red,
        Tier::Review => Color::Yellow,
        Tier::Defer => Color::Green,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patchsense_core::model::{
        Advisory, CvssSignal, Ecosystem, EpssSignal, Finding, FindingSignals, KevSignal, Package,
        Report, ReportContext, Summary,
    };

    fn finding(score: u32, tier: Tier, kev: bool) -> Finding {
        Finding {
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
            tier,
            score,
            signals: FindingSignals {
                cves: vec!["CVE-2021-23337".to_string()],
                cvss: Some(CvssSignal {
                    version: Some("3.1".to_string()),
                    vector: None,
                    base_score: 7.2,
                    source: "osv".to_string(),
                }),
                epss: Some(EpssSignal {
                    score: 0.0123,
                    percentile: 0.78,
                    date: "2026-10-24".to_string(),
                }),
                kev: kev.then(|| KevSignal {
                    date_added: "2026-01-01".to_string(),
                    due_date: "2026-02-01".to_string(),
                    ransomware: "Known".to_string(),
                    name: "lodash".to_string(),
                }),
                breakdown: None,
                explanation: None,
            },
            import_note: None,
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: 1,
            summary: Summary {
                packages_scanned: 1,
                findings: findings.len(),
                critical: findings
                    .iter()
                    .filter(|finding| finding.tier == Tier::Critical)
                    .count(),
                review: 0,
                defer: findings
                    .iter()
                    .filter(|finding| finding.tier == Tier::Defer)
                    .count(),
                max_score: findings
                    .iter()
                    .map(|finding| finding.score)
                    .max()
                    .unwrap_or(0),
                failed: false,
            },
            findings,
            warnings: Vec::new(),
            ignored: Vec::new(),
            context: ReportContext::default(),
        }
    }

    #[test]
    fn colorless_table_matches_the_snapshot_and_has_no_escapes() {
        let report = report(vec![
            finding(100, Tier::Critical, true),
            finding(37, Tier::Defer, false),
        ]);
        let text = render_table(&report, false, 0);
        assert!(!text.contains('\u{1b}'), "{text}");
        insta::assert_snapshot!(text);
    }

    #[test]
    fn the_advisory_cell_shows_the_import_note() {
        let mut row = finding(20, Tier::Defer, false);
        row.signals.cves.clear();
        row.import_note = Some("imported package not seen".to_string());
        let text = render_table(&report(vec![row]), false, 0);
        assert!(text.contains("GHSA-35jh-r3h4-6jhm (imported package not seen)"));
        assert!(text.contains(" 20 "));
    }

    #[test]
    fn color_on_a_tty_uses_escapes_and_min_score_hides_rows() {
        let report = report(vec![
            finding(100, Tier::Critical, true),
            finding(37, Tier::Defer, false),
        ]);
        let colored = render_table(&report, true, 0);
        assert!(colored.contains('\u{1b}'), "{colored}");
        let filtered = render_table(&report, false, 40);
        assert!(!filtered.contains('\u{1b}'));
        assert!(filtered.contains("Critical: 1"));
        assert!(filtered.contains("Defer: 0"));
        assert!(!filtered.contains(" 37 "));
    }

    #[test]
    fn table_prints_the_ai_disclaimer_once() {
        let mut report = report(vec![finding(37, Tier::Defer, false)]);
        report.findings[0].signals.explanation = Some(patchsense_core::model::Explanation {
            agent: "codex".into(),
            text: "Upgrade lodash.".into(),
            disclaimer: "AI explanation, may be wrong".into(),
        });
        let text = render_table(&report, false, 0);
        assert!(text.contains("AI explanation, may be wrong: Upgrade lodash."));
    }
}
