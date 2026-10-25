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
}

/// Priority bucket. The English variant is the JSON value; the label is Indonesian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Score at or above the critical threshold. Label: Kritis.
    Critical,
    /// Score at or above the review threshold. Label: Perlu dicek.
    Review,
    /// Score below the review threshold. Label: Bisa ditunda.
    Defer,
}

impl Tier {
    /// User-facing Indonesian label.
    pub fn label_id(self) -> &'static str {
        match self {
            Self::Critical => "Kritis",
            Self::Review => "Perlu dicek",
            Self::Defer => "Bisa ditunda",
        }
    }
}

/// One package version affected by one advisory.
///
/// Scoring fields are filled in by later tasks. This type is the stable
/// carrier between the OSV client and the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// Scan output. The JSON schema in the product spec is filled in later;
/// `schema_version` is already 1 so callers can tell the generations apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Advisory ids dropped by `ignore`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<String>,
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
    fn tier_labels_are_indonesian() {
        assert_eq!(Tier::Critical.label_id(), "Kritis");
        assert_eq!(Tier::Review.label_id(), "Perlu dicek");
        assert_eq!(Tier::Defer.label_id(), "Bisa ditunda");
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
        };
        let parsed = ParsedLockfile {
            ecosystem: Ecosystem::Npm,
            packages: vec![package.clone()],
            warnings: vec!["baris 12 tidak dipin, dilewati".to_string()],
        };
        let finding = Finding {
            advisory: advisory.clone(),
            package: package.clone(),
            tier: Tier::Defer,
            score: 0,
        };
        let report = Report {
            schema_version: 1,
            findings: vec![finding],
            warnings: vec![],
            summary: Summary::default(),
            ignored: Vec::new(),
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
        assert_eq!(restored.findings[0].tier.label_id(), "Bisa ditunda");
    }
}
