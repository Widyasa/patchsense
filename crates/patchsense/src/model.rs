//! Domain types shared by parsers, the OSV client, and the report.
//!
//! Identifier names are English. Tier labels shown to users are Indonesian,
//! as required by the product spec.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Package ecosystem, serialized as the OSV ecosystem string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    /// npm, pnpm, and yarn.
    #[serde(rename = "npm")]
    Npm,
    /// Python packages on PyPI.
    #[serde(rename = "PyPI")]
    Pypi,
    /// PHP packages on Packagist.
    #[serde(rename = "Packagist")]
    Packagist,
    /// Go modules.
    #[serde(rename = "Go")]
    Go,
    /// Maven artifacts (`groupId:artifactId`).
    #[serde(rename = "Maven")]
    Maven,
    /// Rust crates from crates.io.
    #[serde(rename = "crates.io")]
    CratesIo,
}

impl Ecosystem {
    /// Every ecosystem the MVP scanner understands, in a stable order.
    pub fn all() -> [Self; 6] {
        [
            Self::Npm,
            Self::Pypi,
            Self::Packagist,
            Self::Go,
            Self::Maven,
            Self::CratesIo,
        ]
    }

    /// OSV ecosystem string (`npm`, `PyPI`, `Packagist`, `Go`, `Maven`, `crates.io`).
    pub fn as_osv_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
            Self::Packagist => "Packagist",
            Self::Go => "Go",
            Self::Maven => "Maven",
            Self::CratesIo => "crates.io",
        }
    }

    /// Parse a config or CLI ecosystem name.
    ///
    /// Names are case-insensitive. `npm` covers npm, pnpm, and yarn.
    /// `composer` is `Packagist`. `cargo` is `crates.io`.
    pub fn parse_config_name(name: &str) -> Result<Self, CoreError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "npm" => Ok(Self::Npm),
            "pypi" => Ok(Self::Pypi),
            "packagist" | "composer" => Ok(Self::Packagist),
            "go" => Ok(Self::Go),
            "maven" => Ok(Self::Maven),
            "cargo" | "crates.io" => Ok(Self::CratesIo),
            other => Err(CoreError::UnknownEcosystem {
                name: other.to_string(),
            }),
        }
    }
}

/// One package resolved from a lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// Ecosystem the package is published in.
    pub ecosystem: Ecosystem,
    /// Package name. Maven uses `groupId:artifactId`. PyPI names are PEP 503.
    pub name: String,
    /// Version string as it should be sent to OSV.
    pub version: String,
    /// `Some(true)` direct, `Some(false)` transitive, `None` when unknown.
    pub direct: Option<bool>,
    /// True when the parser knows this is a development dependency.
    #[serde(default)]
    pub dev: bool,
    /// Lockfile path, relative to the scan root when the caller passes one.
    ///
    /// After dedupe this is every contributing path, sorted and joined with `, `.
    pub source_file: String,
    /// Every lockfile that contributed this package, sorted. Empty in parser
    /// output; [`crate::scan`] fills it when paths are merged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_files: Vec<String>,
    /// 1-based line of the package declaration, when the parser records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// Packages and warnings produced by one lockfile parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedLockfile {
    /// Ecosystem of this lockfile.
    pub ecosystem: Ecosystem,
    /// Packages in deterministic order (the parser sorts them).
    pub packages: Vec<Package>,
    /// Non-fatal notes, such as an unpinned requirements line.
    pub warnings: Vec<String>,
}

/// A CVSS (or other) severity entry from OSV `severity[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Severity {
    /// Severity type, for example `CVSS_V3` or `CVSS_V4`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Vector string, or another score representation supplied by OSV.
    pub score: String,
}

/// One Go package named by `affected[].ecosystem_specific.imports`.
///
/// `symbols` is stored when OSV sent it. The import check matches `path`
/// only. An empty list means the advisory did not name symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoImport {
    /// Import path, for example `golang.org/x/crypto/openpgp`.
    pub path: String,
    /// Function or method names inside that package, when OSV listed them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<String>,
}

/// Advisory detail relevant to triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// OSV id, usually a GHSA or PYSEC id.
    pub id: String,
    /// Aliases such as CVE ids.
    pub aliases: Vec<String>,
    /// Short summary from OSV.
    pub summary: String,
    /// Severity vectors.
    pub severity: Vec<Severity>,
    /// Fallback severity from `database_specific.severity`, when present.
    pub database_specific_severity: Option<String>,
    /// Reference URLs.
    pub references: Vec<String>,
    /// Fixed versions that apply to the installed package.
    pub fixed_versions: Vec<String>,
    /// Go import paths from the matching affected entry. Empty for other
    /// ecosystems and for advisories that do not list imports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<GoImport>,
}

/// Priority bucket. The variant name is the JSON value; [`Tier::label`] is the table text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Score at or above the critical threshold. Label: Critical.
    Critical,
    /// Score at or above the review threshold. Label: Review.
    Review,
    /// Score below the review threshold. Label: Defer.
    Defer,
}

impl Tier {
    /// User-facing English label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::Review => "Review",
            Self::Defer => "Defer",
        }
    }
}

/// One package version affected by one advisory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Advisory matched to `package`.
    pub advisory: Advisory,
    /// Installed package.
    pub package: Package,
    /// Priority bucket. Stays `Defer` until enrichment scores the finding.
    pub tier: Tier,
    /// Rounded priority score, 0–100. Zero until enrichment runs.
    #[serde(default)]
    pub score: u32,
    /// CVSS, EPSS, KEV, and the score breakdown. Empty until enrichment runs.
    #[serde(default)]
    pub signals: FindingSignals,
    /// Set when a Go advisory listed import paths and none were found.
    ///
    /// The score and tier are unchanged. Absent when the advisory has no
    /// import data, or when one of the paths was imported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_note: Option<String>,
}

/// Scan output. [`crate::report::render_json`] turns this into PRD §8.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Report schema generation.
    pub schema_version: u32,
    /// Findings, in the order the scan produced them.
    pub findings: Vec<Finding>,
    /// Warnings collected from parsers and the scan.
    pub warnings: Vec<String>,
    /// Counts after ignore rules are applied.
    #[serde(default)]
    pub summary: Summary,
    /// Findings dropped by `ignore`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<IgnoredItem>,
    /// Header fields the JSON document needs. Defaults keep older fixtures small.
    #[serde(default)]
    pub context: ReportContext,
}

/// CVSS, EPSS, KEV, and the component values for one finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FindingSignals {
    /// CVE ids, uppercased.
    #[serde(default)]
    pub cves: Vec<String>,
    /// Chosen CVSS number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CvssSignal>,
    /// EPSS row. `None` when the advisory has no scored CVE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<EpssSignal>,
    /// KEV row. `None` when the advisory is not in the catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kev: Option<KevSignal>,
    /// Component values. `None` until the score engine runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<BreakdownSignal>,
    /// Agent text. `None` until `--explain` succeeds for this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Explanation>,
}

/// CVSS fields stored on a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CvssSignal {
    /// `"3.1"` and similar. Absent for a qualitative fallback.
    pub version: Option<String>,
    /// Vector string. Absent for a qualitative fallback.
    pub vector: Option<String>,
    /// Base score, 0–10.
    pub base_score: f64,
    /// `osv` or `database_specific`.
    pub source: String,
}

/// EPSS fields stored on a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpssSignal {
    /// Probability, 0–1.
    pub score: f64,
    /// Percentile, 0–1.
    pub percentile: f64,
    /// Score date `YYYY-MM-DD`.
    pub date: String,
}

/// KEV fields stored on a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevSignal {
    /// `dateAdded`.
    pub date_added: String,
    /// `dueDate`.
    pub due_date: String,
    /// `Known` or `Unknown`.
    pub ransomware: String,
    /// `vulnerabilityName`.
    pub name: String,
}

/// Unnormalized score components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BreakdownSignal {
    /// KEV component.
    pub kev: f64,
    /// EPSS component.
    pub epss: f64,
    /// CVSS component.
    pub cvss: f64,
    /// Direct-dependency component.
    pub direct: f64,
    /// Fix-available component.
    pub fix_available: f64,
    /// Sum of the configured weights.
    pub total_weight: f64,
}

/// Text from `scan --explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// Agent that wrote `text`.
    pub agent: String,
    /// Agent response.
    pub text: String,
    /// Fixed label required next to AI text.
    pub disclaimer: String,
}

/// One lockfile the scan opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileRecord {
    /// Path relative to the scan root when possible.
    pub path: String,
    /// OSV ecosystem name, or `unknown` when the file name did not match.
    pub ecosystem: String,
    /// Packages parsed from this file.
    pub packages: usize,
    /// `ok` or `error`.
    pub status: String,
    /// Parser notes, or the error text when `status` is `error`.
    pub warnings: Vec<String>,
}

/// A finding removed by an ignore rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoredItem {
    /// Advisory id that matched the rule.
    pub id: String,
    /// `name@version`.
    pub package: String,
    /// Required reason from the config rule.
    pub reason: String,
    /// Inclusive expiry, when the rule has one.
    pub expires: Option<String>,
}

/// Weights copied onto the report so the JSON config block does not need `Config`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightSnapshot {
    /// KEV weight.
    pub kev: f64,
    /// EPSS weight.
    pub epss: f64,
    /// CVSS weight.
    pub cvss: f64,
    /// Direct-dependency weight.
    pub direct: f64,
    /// Fix-available weight.
    pub fix_available: f64,
}

impl Default for WeightSnapshot {
    fn default() -> Self {
        Self {
            kev: 35.0,
            epss: 25.0,
            cvss: 20.0,
            direct: 10.0,
            fix_available: 10.0,
        }
    }
}

/// Header data for the JSON document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportContext {
    /// Path the user asked to scan.
    pub target: String,
    /// UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`.
    pub generated_at: String,
    /// Lockfiles opened during the scan.
    pub lockfiles: Vec<LockfileRecord>,
    /// When OSV data was considered current.
    pub osv_fetched_at: String,
    /// True when the scan did not call the network.
    pub osv_from_cache: bool,
    /// Newest EPSS score date seen, if enrichment ran.
    pub epss_date: Option<String>,
    /// True when the EPSS map was served without a download.
    pub epss_from_cache: bool,
    /// CISA `catalogVersion`, if the catalog was loaded.
    pub kev_catalog_version: Option<String>,
    /// True when the KEV catalog was served without a download.
    pub kev_from_cache: bool,
    /// Weights used for this scan.
    pub weights: WeightSnapshot,
    /// Critical tier cutoff.
    pub threshold_critical: f64,
    /// Review tier cutoff.
    pub threshold_review: f64,
    /// `--fail-on` token (`critical`, `review`, `any`, `never`, or a number).
    pub fail_on: String,
    /// `not_requested`, `ok`, `no_agent_found`, `failed`, or `timeout`.
    pub explain_status: String,
    /// Agent name when `explain_status` is `ok`.
    pub explain_agent: Option<String>,
}

impl Default for ReportContext {
    fn default() -> Self {
        Self {
            target: ".".to_string(),
            generated_at: String::new(),
            lockfiles: Vec::new(),
            osv_fetched_at: String::new(),
            osv_from_cache: false,
            epss_date: None,
            epss_from_cache: false,
            kev_catalog_version: None,
            kev_from_cache: false,
            weights: WeightSnapshot::default(),
            threshold_critical: 70.0,
            threshold_review: 40.0,
            fail_on: "critical".to_string(),
            explain_status: "not_requested".to_string(),
            explain_agent: None,
        }
    }
}

/// Counts the scan uses for `--fail-on` and the report header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Summary {
    /// Packages sent to OSV after dedupe and filters.
    pub packages_scanned: usize,
    /// Findings that were not ignored.
    pub findings: usize,
    /// Findings in the critical tier.
    pub critical: usize,
    /// Findings in the review tier.
    pub review: usize,
    /// Findings in the defer tier.
    pub defer: usize,
    /// Highest rounded score, or 0.
    pub max_score: u32,
    /// True when a finding meets the configured `--fail-on` bar.
    pub failed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_names_map_to_osv_ecosystems() {
        let cases = [
            ("npm", Ecosystem::Npm, "npm"),
            ("NPM", Ecosystem::Npm, "npm"),
            ("pypi", Ecosystem::Pypi, "PyPI"),
            ("PyPI", Ecosystem::Pypi, "PyPI"),
            ("packagist", Ecosystem::Packagist, "Packagist"),
            ("composer", Ecosystem::Packagist, "Packagist"),
            ("Composer", Ecosystem::Packagist, "Packagist"),
            ("go", Ecosystem::Go, "Go"),
            ("GO", Ecosystem::Go, "Go"),
            ("maven", Ecosystem::Maven, "Maven"),
            ("cargo", Ecosystem::CratesIo, "crates.io"),
            ("crates.io", Ecosystem::CratesIo, "crates.io"),
            ("Crates.IO", Ecosystem::CratesIo, "crates.io"),
        ];
        for (input, ecosystem, osv) in cases {
            let parsed = Ecosystem::parse_config_name(input).unwrap_or_else(|err| {
                panic!("config name {input} should parse: {err}");
            });
            assert_eq!(parsed, ecosystem, "config name {input}");
            assert_eq!(parsed.as_osv_str(), osv, "osv name for {input}");
        }
    }

    #[test]
    fn unknown_config_name_is_rejected() {
        let err = Ecosystem::parse_config_name("nuget").unwrap_err();
        let CoreError::UnknownEcosystem { name } = err else {
            panic!("expected UnknownEcosystem");
        };
        assert_eq!(name, "nuget");
    }

    #[test]
    fn tier_labels_are_english() {
        assert_eq!(Tier::Critical.label(), "Critical");
        assert_eq!(Tier::Review.label(), "Review");
        assert_eq!(Tier::Defer.label(), "Defer");
    }

    #[test]
    fn domain_types_roundtrip_through_json() {
        for ecosystem in Ecosystem::all() {
            let json = serde_json::to_string(&ecosystem).expect("serialize ecosystem");
            assert_eq!(json, format!("\"{}\"", ecosystem.as_osv_str()));
            let back: Ecosystem = serde_json::from_str(&json).expect("deserialize ecosystem");
            assert_eq!(back, ecosystem);
        }

        let tier_json = serde_json::to_string(&Tier::Review).unwrap();
        assert_eq!(tier_json, "\"review\"");
        let tier: Tier = serde_json::from_str(&tier_json).unwrap();
        assert_eq!(tier, Tier::Review);

        let package = Package {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            version: "4.17.15".to_string(),
            direct: Some(true),
            dev: false,
            source_file: "package-lock.json".to_string(),
            source_files: Vec::new(),
            line: None,
        };
        let advisory = Advisory {
            id: "GHSA-35jh-r3h4-6jhm".to_string(),
            aliases: vec!["CVE-2021-23337".to_string()],
            summary: "Command Injection in lodash".to_string(),
            severity: vec![Severity {
                kind: "CVSS_V3".to_string(),
                score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H".to_string(),
            }],
            database_specific_severity: Some("HIGH".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()],
            fixed_versions: vec!["4.17.21".to_string()],
            imports: Vec::new(),
        };
        let parsed = ParsedLockfile {
            ecosystem: Ecosystem::Npm,
            packages: vec![package.clone()],
            warnings: vec!["line 12 is not pinned, skipped".to_string()],
        };
        let finding = Finding {
            advisory: advisory.clone(),
            package: package.clone(),
            tier: Tier::Defer,
            score: 0,
            signals: FindingSignals::default(),
            import_note: None,
        };
        let report = Report {
            schema_version: 1,
            findings: vec![finding],
            warnings: vec![],
            summary: Summary::default(),
            ignored: Vec::new(),
            context: ReportContext::default(),
        };

        for value in [
            serde_json::to_value(&package).unwrap(),
            serde_json::to_value(&advisory).unwrap(),
            serde_json::to_value(&parsed).unwrap(),
            serde_json::to_value(&report).unwrap(),
        ] {
            let text = serde_json::to_string(&value).unwrap();
            let back: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(back, value);
        }

        let restored: Report =
            serde_json::from_value(serde_json::to_value(&report).unwrap()).unwrap();
        assert_eq!(restored.schema_version, 1);
        assert_eq!(restored.findings[0].advisory.id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(restored.findings[0].package.name, "lodash");
        assert_eq!(restored.findings[0].tier.label(), "Defer");
        assert!(restored.findings[0].advisory.imports.is_empty());
        assert!(restored.findings[0].import_note.is_none());
    }

    #[test]
    fn older_advisory_json_without_imports_still_parses() {
        let advisory: Advisory = serde_json::from_str(
            r#"{"id":"GO-1","aliases":[],"summary":"s","severity":[],"database_specific_severity":null,"references":[],"fixed_versions":[]}"#,
        )
        .expect("advisory");
        assert!(advisory.imports.is_empty());
        let finding: Finding = serde_json::from_str(
            r#"{"advisory":{"id":"GO-1","aliases":[],"summary":"s","severity":[],"database_specific_severity":null,"references":[],"fixed_versions":[]},"package":{"ecosystem":"Go","name":"golang.org/x/crypto","version":"v0.1.0","direct":null,"dev":false,"source_file":"go.sum"},"tier":"defer"}"#,
        )
        .expect("finding");
        assert!(finding.import_note.is_none());
        assert!(finding.advisory.imports.is_empty());
        assert_eq!(finding.score, 0);
    }
}
