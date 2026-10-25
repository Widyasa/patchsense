//! `patchsense.toml` (PRD §7).
//!
//! Unknown fields are rejected. Search starts at the scan directory and stops
//! at the git root. Precedence is flag, then environment, then the file, then
//! the built-in default (PRD AC9.3).

use std::path::{Path, PathBuf};

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::model::Ecosystem;

/// Loaded file plus warnings. Expired ignore rules are already removed.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedConfig {
    /// Config after precedence is applied.
    pub config: Config,
    /// File that was read. `None` when only defaults and overrides are in use.
    pub path: Option<PathBuf>,
    /// Non-fatal notes, including expired ignore rules.
    pub warnings: Vec<String>,
}

/// Values read from the environment. Already parsed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EnvInput {
    /// `PATCHSENSE_FAIL_ON`.
    pub fail_on: Option<FailOn>,
    /// `PATCHSENSE_AGENT`.
    pub agent: Option<ExplainAgent>,
}

/// Values read from CLI flags. `None` means the flag was not passed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlagInput {
    /// `--fail-on`.
    pub fail_on: Option<FailOn>,
    /// `--ecosystem`. `None` means the flag was omitted.
    pub ecosystems: Option<Vec<Ecosystem>>,
    /// `--no-dev` sets this to `Some(false)`.
    pub include_dev: Option<bool>,
    /// `--agent`.
    pub agent: Option<ExplainAgent>,
    /// `--exclude` values. These are added to the file list.
    pub exclude: Vec<String>,
}

/// Inputs for [`load_config`].
#[derive(Debug, Clone)]
pub struct LoadRequest<'a> {
    /// Directory or lockfile being scanned.
    pub start: &'a Path,
    /// `--config`.
    pub config_flag: Option<&'a Path>,
    /// `PATCHSENSE_CONFIG`.
    pub config_env: Option<&'a Path>,
    /// `YYYY-MM-DD` used to expire ignore rules.
    pub today: &'a str,
    /// Environment overrides.
    pub env: EnvInput,
    /// Flag overrides.
    pub flags: FlagInput,
}

/// Full configuration.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Document version. Only `1` is accepted.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Scan filters.
    #[serde(default)]
    pub scan: ScanSection,
    /// Score weights, EPSS mode, and tier thresholds.
    #[serde(default)]
    pub score: ScoreSection,
    /// Cache TTLs.
    #[serde(default)]
    pub cache: CacheSection,
    /// Report shaping.
    #[serde(default)]
    pub output: OutputSection,
    /// Optional agent explanation.
    #[serde(default)]
    pub explain: ExplainSection,
    /// Advisory suppressions. Expired rules are removed by [`load_config`].
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,
}

/// `[scan]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSection {
    /// Ecosystems to scan. The default is every supported ecosystem.
    #[serde(default = "default_ecosystems", deserialize_with = "de_ecosystems")]
    pub ecosystems: Vec<Ecosystem>,
    /// Extra glob patterns skipped by discovery.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// When false, dev dependencies are dropped.
    #[serde(default = "default_true")]
    pub include_dev: bool,
    /// Exit-code threshold. Applied by the scan pipeline.
    #[serde(default)]
    pub fail_on: FailOn,
}

/// `[score]`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreSection {
    /// Component weights.
    #[serde(default)]
    pub weights: Weights,
    /// How EPSS becomes a 0–1 factor.
    #[serde(default)]
    pub epss: EpssSection,
    /// Tier cutoffs.
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Weight used when `direct` is unknown.
    #[serde(default)]
    pub unknown_direct: UnknownDirect,
}

/// `[score.weights]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    /// KEV component.
    #[serde(default = "default_weight_kev", deserialize_with = "de_f64")]
    pub kev: f64,
    /// EPSS component.
    #[serde(default = "default_weight_epss", deserialize_with = "de_f64")]
    pub epss: f64,
    /// CVSS component.
    #[serde(default = "default_weight_cvss", deserialize_with = "de_f64")]
    pub cvss: f64,
    /// Direct-dependency component.
    #[serde(default = "default_weight_direct", deserialize_with = "de_f64")]
    pub direct: f64,
    /// Fix-available component.
    #[serde(default = "default_weight_fix", deserialize_with = "de_f64")]
    pub fix_available: f64,
}

/// `[score.epss]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpssSection {
    /// `probability` or `percentile`.
    #[serde(default)]
    pub mode: EpssMode,
    /// Probability that receives the full EPSS weight.
    #[serde(default = "default_saturation", deserialize_with = "de_f64")]
    pub saturation: f64,
}

/// `[score.thresholds]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    /// Score at or above this value is Kritis.
    #[serde(default = "default_critical", deserialize_with = "de_f64")]
    pub critical: f64,
    /// Score at or above this value is Perlu dicek.
    #[serde(default = "default_review", deserialize_with = "de_f64")]
    pub review: f64,
}

/// `[score.unknown_direct]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownDirect {
    /// Fraction of the direct weight used when the parser does not know.
    #[serde(default = "default_true_f64", deserialize_with = "de_f64")]
    pub weight_fraction: f64,
}

/// `[cache]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSection {
    /// OSV body TTL in hours.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours_osv: u64,
    /// EPSS TTL in hours.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours_epss: u64,
    /// KEV catalog TTL in hours.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours_kev: u64,
}

/// `[output]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    /// Rows in the markdown comment table.
    #[serde(default = "default_output_top")]
    pub top: u32,
}

/// `[explain]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainSection {
    /// Which agent to ask.
    #[serde(default)]
    pub agent: ExplainAgent,
    /// Findings sent to the agent.
    #[serde(default = "default_explain_top")]
    pub top: u32,
    /// Prompt language.
    #[serde(default)]
    pub lang: ExplainLang,
    /// Agent timeout.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// One `[[ignore]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    /// OSV id or CVE id.
    pub id: String,
    /// Why the finding is suppressed. Required.
    pub reason: String,
    /// Inclusive last day `YYYY-MM-DD`. Absent means the rule does not expire.
    #[serde(default)]
    pub expires: Option<String>,
}

/// `--fail-on` / `scan.fail_on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailOn {
    /// Score at or above the critical threshold.
    #[default]
    Critical,
    /// Score at or above the review threshold.
    Review,
    /// Any finding.
    Any,
    /// Never fail the scan because of a finding.
    Never,
    /// Explicit numeric threshold, 0–100.
    Score(u8),
}

/// EPSS normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EpssMode {
    /// `min(1, probability / saturation)`.
    #[default]
    Probability,
    /// Use the EPSS percentile directly.
    Percentile,
}

/// Agent selected for `--explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExplainAgent {
    /// First installed agent.
    #[default]
    Auto,
    /// OpenAI Codex CLI.
    Codex,
    /// Claude Code.
    Claude,
    /// Cursor agent CLI.
    Cursor,
}

/// Prompt language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExplainLang {
    /// Indonesian.
    #[default]
    Id,
    /// English.
    En,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            scan: ScanSection::default(),
            score: ScoreSection::default(),
            cache: CacheSection::default(),
            output: OutputSection::default(),
            explain: ExplainSection::default(),
            ignore: Vec::new(),
        }
    }
}

impl Default for ScanSection {
    fn default() -> Self {
        Self {
            ecosystems: default_ecosystems(),
            exclude: Vec::new(),
            include_dev: true,
            fail_on: FailOn::Critical,
        }
    }
}

impl Default for Weights {
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

impl Default for EpssSection {
    fn default() -> Self {
        Self {
            mode: EpssMode::Probability,
            saturation: 0.10,
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            critical: 70.0,
            review: 40.0,
        }
    }
}

impl Default for UnknownDirect {
    fn default() -> Self {
        Self {
            weight_fraction: 1.0,
        }
    }
}

impl Default for CacheSection {
    fn default() -> Self {
        Self {
            ttl_hours_osv: 24,
            ttl_hours_epss: 24,
            ttl_hours_kev: 24,
        }
    }
}

impl Default for OutputSection {
    fn default() -> Self {
        Self { top: 20 }
    }
}

impl Default for ExplainSection {
    fn default() -> Self {
        Self {
            agent: ExplainAgent::Auto,
            top: 10,
            lang: ExplainLang::Id,
            timeout_secs: 120,
        }
    }
}

impl FailOn {
    /// Parse `critical`, `review`, `any`, `never`, or a number 0–100.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "review" => Ok(Self::Review),
            "any" => Ok(Self::Any),
            "never" => Ok(Self::Never),
            other => match other.parse::<u8>() {
                Ok(score) if score <= 100 => Ok(Self::Score(score)),
                _ => Err(CoreError::parse(
                    "fail_on",
                    None,
                    format!("unknown fail_on `{raw}`"),
                )),
            },
        }
    }
}

impl ExplainAgent {
    /// Parse `auto`, `codex`, `claude`, or `cursor`.
    pub fn parse(raw: &str) -> Result<Self, CoreError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            "cursor" => Ok(Self::Cursor),
            _ => Err(CoreError::parse(
                "agent",
                None,
                format!("unknown agent `{raw}`"),
            )),
        }
    }
}

impl Config {
    /// True when `ecosystems` is the full supported set.
    pub fn scans_every_ecosystem(&self) -> bool {
        let mut got = self.scan.ecosystems.clone();
        got.sort();
        got.dedup();
        got == Ecosystem::all().to_vec()
    }
}

/// Read process env vars that override the file. Missing vars are `None`.
pub fn env_from_process() -> Result<EnvInput, CoreError> {
    let fail_on = match std::env::var("PATCHSENSE_FAIL_ON") {
        Ok(value) => Some(FailOn::parse(&value)?),
        Err(std::env::VarError::NotPresent) => None,
        Err(err) => {
            return Err(CoreError::parse(
                "PATCHSENSE_FAIL_ON",
                None,
                err.to_string(),
            ))
        }
    };
    let agent = match std::env::var("PATCHSENSE_AGENT") {
        Ok(value) => Some(ExplainAgent::parse(&value)?),
        Err(std::env::VarError::NotPresent) => None,
        Err(err) => return Err(CoreError::parse("PATCHSENSE_AGENT", None, err.to_string())),
    };
    Ok(EnvInput { fail_on, agent })
}

/// Load, validate, apply precedence, and drop expired ignore rules.
pub fn load_config(request: &LoadRequest<'_>) -> Result<LoadedConfig, CoreError> {
    let (path, mut config) = read_config(request)?;
    apply_precedence(&mut config, &request.env, &request.flags);
    let (ignore, warnings) = partition_ignores(&config.ignore, request.today)?;
    config.ignore = ignore;
    Ok(LoadedConfig {
        config,
        path,
        warnings,
    })
}

/// `YYYY-MM-DD` for the current UTC day.
pub fn today_utc() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    ymd_from_unix_seconds(seconds)
}

/// Gregorian date for a Unix timestamp.
pub fn ymd_from_unix_seconds(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}")
}

fn read_config(request: &LoadRequest<'_>) -> Result<(Option<PathBuf>, Config), CoreError> {
    let path = if let Some(flag) = request.config_flag {
        Some(flag.to_path_buf())
    } else if let Some(env) = request.config_env {
        Some(env.to_path_buf())
    } else {
        find_config_file(request.start)
    };
    let Some(path) = path else {
        return Ok((None, Config::default()));
    };
    let text = std::fs::read_to_string(&path).map_err(|source| CoreError::Io {
        path: path.clone(),
        source,
    })?;
    let config = parse_config_str(&path, &text)?;
    Ok((Some(path), config))
}

/// Parse TOML text. `path` is only used in the error.
pub fn parse_config_str(path: &Path, text: &str) -> Result<Config, CoreError> {
    let config: Config = toml::from_str(text)
        .map_err(|err| CoreError::parse(path, None, err.message().to_string()))?;
    validate(&config, path)?;
    Ok(config)
}

fn validate(config: &Config, path: &Path) -> Result<(), CoreError> {
    if config.schema_version != 1 {
        return Err(CoreError::parse(
            path,
            None,
            format!("unsupported schema_version {}", config.schema_version),
        ));
    }
    if !(config.score.epss.saturation.is_finite() && config.score.epss.saturation > 0.0) {
        return Err(CoreError::parse(
            path,
            None,
            "score.epss.saturation must be a number greater than 0",
        ));
    }
    let weights = &config.score.weights;
    for (name, value) in [
        ("kev", weights.kev),
        ("epss", weights.epss),
        ("cvss", weights.cvss),
        ("direct", weights.direct),
        ("fix_available", weights.fix_available),
    ] {
        if !(value.is_finite() && value >= 0.0) {
            return Err(CoreError::parse(
                path,
                None,
                format!("score.weights.{name} must be a number >= 0"),
            ));
        }
    }
    for rule in &config.ignore {
        if rule.reason.trim().is_empty() {
            return Err(CoreError::parse(
                path,
                None,
                format!("ignore {} is missing reason", rule.id),
            ));
        }
        if let Some(expires) = &rule.expires {
            if !is_iso_date(expires) {
                return Err(CoreError::parse(
                    path,
                    None,
                    format!(
                        "ignore {} has invalid expires `{expires}`, expected YYYY-MM-DD",
                        rule.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Walk parents from `start` through the git root, looking for `patchsense.toml`.
pub fn find_config_file(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };
    loop {
        let candidate = dir.join("patchsense.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(".git").exists() {
            return None;
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn apply_precedence(config: &mut Config, env: &EnvInput, flags: &FlagInput) {
    if let Some(fail_on) = env.fail_on {
        config.scan.fail_on = fail_on;
    }
    if let Some(agent) = env.agent {
        config.explain.agent = agent;
    }
    if let Some(fail_on) = flags.fail_on {
        config.scan.fail_on = fail_on;
    }
    if let Some(ecosystems) = &flags.ecosystems {
        config.scan.ecosystems = ecosystems.clone();
    }
    if let Some(include_dev) = flags.include_dev {
        config.scan.include_dev = include_dev;
    }
    if let Some(agent) = flags.agent {
        config.explain.agent = agent;
    }
    for pattern in &flags.exclude {
        if !config
            .scan
            .exclude
            .iter()
            .any(|existing| existing == pattern)
        {
            config.scan.exclude.push(pattern.clone());
        }
    }
}

/// Split ignore rules into those still in force and warning strings.
///
/// `expires` is inclusive: a rule whose date equals `today` still applies.
pub fn partition_ignores(
    rules: &[IgnoreRule],
    today: &str,
) -> Result<(Vec<IgnoreRule>, Vec<String>), CoreError> {
    if !is_iso_date(today) {
        return Err(CoreError::parse(
            "today",
            None,
            format!("invalid date `{today}`"),
        ));
    }
    let mut active = Vec::new();
    let mut warnings = Vec::new();
    for rule in rules {
        match &rule.expires {
            Some(expires) if expires.as_str() < today => {
                warnings.push(format!(
                    "ignore {} kedaluwarsa pada {expires} dan tidak dipakai",
                    rule.id
                ));
            }
            _ => active.push(rule.clone()),
        }
    }
    Ok((active, warnings))
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return false;
    }
    let year: u32 = value[0..4].parse().unwrap_or(0);
    let month: u32 = value[5..7].parse().unwrap_or(0);
    let day: u32 = value[8..10].parse().unwrap_or(0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn default_schema_version() -> u32 {
    1
}

fn default_ecosystems() -> Vec<Ecosystem> {
    Ecosystem::all().to_vec()
}

fn default_true() -> bool {
    true
}

fn default_weight_kev() -> f64 {
    35.0
}

fn default_weight_epss() -> f64 {
    25.0
}

fn default_weight_cvss() -> f64 {
    20.0
}

fn default_weight_direct() -> f64 {
    10.0
}

fn default_weight_fix() -> f64 {
    10.0
}

fn default_saturation() -> f64 {
    0.10
}

fn default_critical() -> f64 {
    70.0
}

fn default_review() -> f64 {
    40.0
}

fn default_true_f64() -> f64 {
    1.0
}

fn default_ttl_hours() -> u64 {
    24
}

fn default_output_top() -> u32 {
    20
}

fn default_explain_top() -> u32 {
    10
}

fn default_timeout() -> u64 {
    120
}

fn de_f64<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    struct NumberVisitor;
    impl Visitor<'_> for NumberVisitor {
        type Value = f64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a number")
        }

        fn visit_f64<E: de::Error>(self, value: f64) -> Result<f64, E> {
            Ok(value)
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<f64, E> {
            Ok(value as f64)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<f64, E> {
            Ok(value as f64)
        }
    }
    deserializer.deserialize_any(NumberVisitor)
}

fn de_ecosystems<'de, D>(deserializer: D) -> Result<Vec<Ecosystem>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Vec::<String>::deserialize(deserializer)?;
    names
        .into_iter()
        .map(|name| {
            Ecosystem::parse_config_name(&name).map_err(|err| de::Error::custom(err.to_string()))
        })
        .collect()
}

impl<'de> Deserialize<'de> for FailOn {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FailVisitor;
        impl Visitor<'_> for FailVisitor {
            type Value = FailOn;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("critical, review, any, never, or a score 0-100")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<FailOn, E> {
                FailOn::parse(value).map_err(|err| E::custom(err.to_string()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<FailOn, E> {
                self.visit_str(&value)
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<FailOn, E> {
                if (0..=100).contains(&value) {
                    Ok(FailOn::Score(value as u8))
                } else {
                    Err(E::custom("fail_on score must be 0-100"))
                }
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<FailOn, E> {
                if value <= 100 {
                    Ok(FailOn::Score(value as u8))
                } else {
                    Err(E::custom("fail_on score must be 0-100"))
                }
            }
        }
        deserializer.deserialize_any(FailVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRD_EXAMPLE: &str = r#"
schema_version = 1

[scan]
ecosystems = ["npm", "pypi", "packagist", "go", "maven", "cargo"]
exclude = ["examples/**", "fixtures/**"]
include_dev = true
fail_on = "critical"

[score.weights]
kev = 35
epss = 25
cvss = 20
direct = 10
fix_available = 10

[score.epss]
mode = "probability"
saturation = 0.10

[score.thresholds]
critical = 70
review = 40

[score.unknown_direct]
weight_fraction = 1.0

[cache]
ttl_hours_osv = 24
ttl_hours_epss = 24
ttl_hours_kev = 24

[output]
top = 20

[explain]
agent = "auto"
top = 10
lang = "id"
timeout_secs = 120

[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Hanya dipakai di script build, tidak terekspos"
expires = "2027-01-31"
"#;

    #[test]
    fn prd_example_parses_exactly() {
        let config = parse_config_str(Path::new("patchsense.toml"), PRD_EXAMPLE).expect("parse");
        assert_eq!(config.schema_version, 1);
        assert_eq!(config.scan.ecosystems, Ecosystem::all().to_vec());
        assert_eq!(
            config.scan.exclude,
            vec!["examples/**".to_string(), "fixtures/**".to_string()]
        );
        assert!(config.scan.include_dev);
        assert_eq!(config.scan.fail_on, FailOn::Critical);
        assert_eq!(config.score.weights, Weights::default());
        assert_eq!(config.score.epss.mode, EpssMode::Probability);
        assert!((config.score.epss.saturation - 0.10).abs() < 1e-9);
        assert_eq!(config.score.thresholds, Thresholds::default());
        assert!((config.score.unknown_direct.weight_fraction - 1.0).abs() < 1e-9);
        assert_eq!(config.cache, CacheSection::default());
        assert_eq!(config.output.top, 20);
        assert_eq!(config.explain.agent, ExplainAgent::Auto);
        assert_eq!(config.explain.top, 10);
        assert_eq!(config.explain.lang, ExplainLang::Id);
        assert_eq!(config.explain.timeout_secs, 120);
        assert_eq!(config.ignore.len(), 1);
        assert_eq!(config.ignore[0].id, "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(
            config.ignore[0].reason,
            "Hanya dipakai di script build, tidak terekspos"
        );
        assert_eq!(config.ignore[0].expires.as_deref(), Some("2027-01-31"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = parse_config_str(Path::new("patchsense.toml"), "not_a_field = true\n")
            .expect_err("unknown");
        let message = err.to_string();
        assert!(
            message.contains("not_a_field") || message.contains("unknown"),
            "{message}"
        );
    }

    #[test]
    fn missing_ignore_reason_is_rejected() {
        let toml = "[[ignore]]\nid = \"GHSA-1111-2222-3333\"\n";
        let err = parse_config_str(Path::new("patchsense.toml"), toml).expect_err("reason");
        assert!(err.to_string().contains("reason"), "{err}");
    }

    #[test]
    fn flag_beats_env_beats_file_beats_default() {
        let file = parse_config_str(
            Path::new("patchsense.toml"),
            "[scan]\nfail_on = \"critical\"\necosystems = [\"npm\"]\ninclude_dev = true\n[explain]\nagent = \"auto\"\n",
        )
        .expect("file");
        let from_file = apply_only(file.clone(), EnvInput::default(), FlagInput::default());
        assert_eq!(from_file.scan.fail_on, FailOn::Critical);
        assert_eq!(from_file.scan.ecosystems, vec![Ecosystem::Npm]);

        let from_env = apply_only(
            file.clone(),
            EnvInput {
                fail_on: Some(FailOn::Review),
                agent: Some(ExplainAgent::Claude),
            },
            FlagInput::default(),
        );
        assert_eq!(from_env.scan.fail_on, FailOn::Review);
        assert_eq!(from_env.explain.agent, ExplainAgent::Claude);

        let from_flag = apply_only(
            file,
            EnvInput {
                fail_on: Some(FailOn::Review),
                agent: Some(ExplainAgent::Claude),
            },
            FlagInput {
                fail_on: Some(FailOn::Never),
                ecosystems: Some(vec![Ecosystem::Pypi]),
                include_dev: Some(false),
                agent: Some(ExplainAgent::Cursor),
                exclude: vec!["vendor/**".to_string()],
            },
        );
        assert_eq!(from_flag.scan.fail_on, FailOn::Never);
        assert_eq!(from_flag.scan.ecosystems, vec![Ecosystem::Pypi]);
        assert!(!from_flag.scan.include_dev);
        assert_eq!(from_flag.explain.agent, ExplainAgent::Cursor);
        assert_eq!(from_flag.scan.exclude, vec!["vendor/**".to_string()]);

        let defaults = apply_only(Config::default(), EnvInput::default(), FlagInput::default());
        assert_eq!(defaults.scan.fail_on, FailOn::Critical);
        assert!(defaults.scans_every_ecosystem());
        assert!(defaults.scan.include_dev);
        assert_eq!(defaults.explain.agent, ExplainAgent::Auto);
    }

    #[test]
    fn expired_ignore_warns_and_is_dropped() {
        let ignore = vec![
            IgnoreRule {
                id: "GHSA-old".to_string(),
                reason: "sudah lewat".to_string(),
                expires: Some("2020-01-01".to_string()),
            },
            IgnoreRule {
                id: "GHSA-today".to_string(),
                reason: "masih hari ini".to_string(),
                expires: Some("2026-10-25".to_string()),
            },
            IgnoreRule {
                id: "GHSA-open".to_string(),
                reason: "tanpa batas".to_string(),
                expires: None,
            },
        ];
        let (active, warnings) = partition_ignores(&ignore, "2026-10-25").expect("dates");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("GHSA-old"));
        assert!(warnings[0].contains("kedaluwarsa"));
        assert_eq!(
            active
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            vec!["GHSA-today", "GHSA-open"]
        );
    }

    #[test]
    fn discovery_stops_at_the_git_root() {
        let root = tempfile::tempdir().expect("temp");
        let repo = root.path().join("repo");
        std::fs::create_dir_all(repo.join("nested")).expect("nested");
        std::fs::create_dir(repo.join(".git")).expect("git");
        std::fs::write(root.path().join("patchsense.toml"), "schema_version = 1\n").expect("outer");
        std::fs::write(
            repo.join("patchsense.toml"),
            "[scan]\nfail_on = \"never\"\n",
        )
        .expect("inner");
        let found = find_config_file(&repo.join("nested").join("child.lock")).expect("found");
        assert_eq!(found, repo.join("patchsense.toml"));

        let bare = root.path().join("bare");
        std::fs::create_dir_all(bare.join(".git")).expect("git");
        assert!(find_config_file(&bare).is_none());
    }

    #[test]
    fn explicit_config_flag_beats_a_discovered_file() {
        let root = tempfile::tempdir().expect("temp");
        std::fs::create_dir(root.path().join(".git")).expect("git");
        std::fs::write(
            root.path().join("patchsense.toml"),
            "[scan]\nfail_on = \"any\"\n",
        )
        .expect("discovered");
        let flagged = root.path().join("other.toml");
        std::fs::write(&flagged, "[scan]\nfail_on = \"never\"\n").expect("flag");
        let loaded = load_config(&LoadRequest {
            start: root.path(),
            config_flag: Some(&flagged),
            config_env: None,
            today: "2026-10-25",
            env: EnvInput {
                fail_on: Some(FailOn::Review),
                agent: None,
            },
            flags: FlagInput::default(),
        })
        .expect("load");
        assert_eq!(loaded.path.as_deref(), Some(flagged.as_path()));
        assert_eq!(loaded.config.scan.fail_on, FailOn::Review);
    }

    #[test]
    fn unix_epoch_and_a_known_day_format() {
        assert_eq!(ymd_from_unix_seconds(0), "1970-01-01");
        assert_eq!(ymd_from_unix_seconds(1_792_886_400), "2026-10-25");
    }

    fn apply_only(mut config: Config, env: EnvInput, flags: FlagInput) -> Config {
        apply_precedence(&mut config, &env, &flags);
        config
    }
}
