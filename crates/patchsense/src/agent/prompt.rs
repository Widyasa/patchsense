//! Prompt text for `scan --explain`.
#![allow(dead_code)] // Called by `scan --explain` in W5-T9.
//!
//! The prompt is the process argument, so it stays under the Windows command
//! line limit. Extra findings are dropped from the end until it fits. A single
//! oversized finding loses references, then summary text, before the prompt is
//! hard-cut.

use patchsense_core::model::{Finding, Report};
use serde_json::json;

/// Characters reserved for the prompt itself.
///
/// Windows rejects a command line around 32,767 characters. 30,000 leaves room
/// for the program path and the adapter flags.
pub const MAX_PROMPT_CHARS: usize = 30_000;

/// Language of the instructions wrapped around the finding JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptLang {
    /// Bahasa Indonesia.
    Id,
    /// English.
    En,
}

/// Build the explain prompt from the highest-ranked findings.
///
/// `top` is the requested count. The returned text never exceeds
/// [`MAX_PROMPT_CHARS`]. Findings stay in the report's existing order.
pub fn build_prompt(report: &Report, top: usize, lang: PromptLang) -> String {
    let available = report.findings.len();
    let mut count = top.min(available);
    loop {
        let prompt = render(report, count, lang);
        if chars(&prompt) <= MAX_PROMPT_CHARS {
            return prompt;
        }
        if count <= 1 {
            return fit_oversized(report, lang);
        }
        count -= 1;
    }
}

fn render(report: &Report, count: usize, lang: PromptLang) -> String {
    let rows: Vec<_> = report
        .findings
        .iter()
        .take(count)
        .map(compact_finding)
        .collect();
    let data = serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string());
    format!(
        "{instructions}\n\n{heading}\n\nData (JSON):\n{data}\n",
        instructions = instructions(lang),
        heading = heading(lang, count, report.findings.len()),
    )
}

fn heading(lang: PromptLang, count: usize, available: usize) -> String {
    match lang {
        PromptLang::Id => format!("Temuan: {count} dari {available}"),
        PromptLang::En => format!("Findings: {count} of {available}"),
    }
}

fn instructions(lang: PromptLang) -> &'static str {
    match lang {
        PromptLang::Id => {
            "Anda menjelaskan temuan kerentanan dependency. Jawab dalam bahasa Indonesia.\n\
Untuk setiap temuan: satu paragraf dampak, lalu satu langkah perbaikan.\n\
Jangan mengarang versi. Kutip hanya versi fix dan link yang ada di data.\n\
Jika data tidak punya versi fix, katakan bahwa versi perbaikan tidak tersedia."
        }
        PromptLang::En => {
            "You explain dependency vulnerability findings. Answer in English.\n\
For each finding: one paragraph on impact, then one remediation step.\n\
Do not invent versions. Quote only fixed versions and links present in the data.\n\
If a finding has no fixed version, say that no fix version is available."
        }
    }
}

fn compact_finding(finding: &Finding) -> serde_json::Value {
    json!({
        "id": finding.advisory.id,
        "package": finding.package.name,
        "ecosystem": finding.package.ecosystem.as_osv_str(),
        "version": finding.package.version,
        "fixed_versions": finding.advisory.fixed_versions,
        "score": finding.score,
        "tier": finding.tier.label_id(),
        "summary": finding.advisory.summary,
        "breakdown": finding.signals.breakdown,
        "kev": finding.signals.kev.is_some(),
        "epss": finding.signals.epss.as_ref().map(|item| item.score),
        "references": finding.advisory.references,
    })
}

fn fit_oversized(report: &Report, lang: PromptLang) -> String {
    let Some(finding) = report.findings.first() else {
        return trim_chars(&render(report, 0, lang));
    };
    let mut references = finding.advisory.references.clone();
    let mut summary = finding.advisory.summary.clone();
    loop {
        let row = json!({
            "id": finding.advisory.id,
            "package": finding.package.name,
            "ecosystem": finding.package.ecosystem.as_osv_str(),
            "version": finding.package.version,
            "fixed_versions": finding.advisory.fixed_versions,
            "score": finding.score,
            "tier": finding.tier.label_id(),
            "summary": summary,
            "breakdown": finding.signals.breakdown,
            "kev": finding.signals.kev.is_some(),
            "epss": finding.signals.epss.as_ref().map(|item| item.score),
            "references": references,
        });
        let data = serde_json::to_string_pretty(&vec![row]).unwrap_or_else(|_| "[]".to_string());
        let prompt = format!(
            "{instructions}\n\n{heading}\n\nData (JSON):\n{data}\n",
            instructions = instructions(lang),
            heading = heading(lang, 1, report.findings.len()),
        );
        if chars(&prompt) <= MAX_PROMPT_CHARS {
            return prompt;
        }
        if !references.is_empty() {
            references.pop();
            continue;
        }
        if !summary.is_empty() {
            let keep = summary.chars().count() / 2;
            summary = summary.chars().take(keep).collect();
            continue;
        }
        return trim_chars(&prompt);
    }
}

fn trim_chars(text: &str) -> String {
    let mut trimmed: String = text
        .chars()
        .take(MAX_PROMPT_CHARS.saturating_sub(12))
        .collect();
    trimmed.push_str("\n[truncated]\n");
    trimmed
}

fn chars(text: &str) -> usize {
    text.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use patchsense_core::model::{
        Advisory, BreakdownSignal, Ecosystem, EpssSignal, Finding, FindingSignals, KevSignal,
        Package, Report, ReportContext, Summary, Tier,
    };

    fn sample(score: u32, references: Vec<String>) -> Finding {
        Finding {
            advisory: Advisory {
                id: "GHSA-35jh-r3h4-6jhm".to_string(),
                aliases: vec!["CVE-2021-23337".to_string()],
                summary: "Command Injection in lodash".to_string(),
                severity: Vec::new(),
                database_specific_severity: None,
                references,
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
            tier: Tier::Critical,
            score,
            signals: FindingSignals {
                cves: vec!["CVE-2021-23337".to_string()],
                cvss: None,
                epss: Some(EpssSignal {
                    score: 0.0123,
                    percentile: 0.78,
                    date: "2026-10-24".to_string(),
                }),
                kev: Some(KevSignal {
                    date_added: "2026-01-01".to_string(),
                    due_date: "2026-02-01".to_string(),
                    ransomware: "Known".to_string(),
                    name: "lodash".to_string(),
                }),
                breakdown: Some(BreakdownSignal {
                    kev: 35.0,
                    epss: 3.075,
                    cvss: 14.4,
                    direct: 10.0,
                    fix_available: 10.0,
                    total_weight: 100.0,
                }),
                explanation: None,
            },
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            schema_version: 1,
            summary: Summary {
                findings: findings.len(),
                ..Summary::default()
            },
            findings,
            warnings: Vec::new(),
            ignored: Vec::new(),
            context: ReportContext::default(),
        }
    }

    #[test]
    fn indonesian_prompt_matches_the_snapshot() {
        let text = build_prompt(
            &report(vec![sample(
                88,
                vec!["https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm".into()],
            )]),
            5,
            PromptLang::Id,
        );
        assert!(text.contains("bahasa Indonesia"));
        assert!(text.contains("GHSA-35jh-r3h4-6jhm"));
        assert!(text.contains("4.17.21"));
        assert!(chars(&text) <= MAX_PROMPT_CHARS);
        insta::assert_snapshot!(text);
    }

    #[test]
    fn english_prompt_matches_the_snapshot() {
        let text = build_prompt(
            &report(vec![sample(
                88,
                vec!["https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm".into()],
            )]),
            5,
            PromptLang::En,
        );
        assert!(text.contains("Answer in English"));
        assert!(text.contains("Do not invent versions"));
        insta::assert_snapshot!(text);
    }

    #[test]
    fn a_large_report_is_cut_until_it_fits() {
        let findings: Vec<_> = (0..40)
            .map(|index| {
                let mut finding = sample(
                    100 - index,
                    (0..30)
                        .map(|link| {
                            format!(
                                "https://example.test/advisory/{index}/{link}/{}",
                                "x".repeat(80)
                            )
                        })
                        .collect(),
                );
                finding.advisory.id = format!("GHSA-load-{index:04}");
                finding
            })
            .collect();
        let full = render(&report(findings.clone()), 40, PromptLang::Id);
        assert!(chars(&full) > MAX_PROMPT_CHARS);
        let text = build_prompt(&report(findings), 40, PromptLang::Id);
        assert!(chars(&text) <= MAX_PROMPT_CHARS, "{}", chars(&text));
        assert!(text.contains("GHSA-load-0000"));
        assert!(!text.contains("GHSA-load-0039"));
        assert!(text.contains("Temuan:"));
    }
}
