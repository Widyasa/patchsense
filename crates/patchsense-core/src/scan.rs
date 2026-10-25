//! Scan orchestration: find lockfiles, parse them, load OSV advisories, and
//! optionally score them.
//!
//! [`ScanOptions::enrich`] fetches EPSS and KEV, merges aliases, and applies
//! the priority score. The CLI turns it on. Library tests leave it off so a
//! scripted HTTP client is not asked for enrichment responses.
//! [`Summary::failed`] follows [`ScanOptions::fail_on`]. The binary maps that
//! flag to exit code 1.
//!
//! `--keep-going` (the default) turns a bad lockfile into a warning unless
//! every lockfile failed. Packages are deduped on ecosystem, name, and version
//! before the OSV query. `--ecosystem` and `--no-dev` drop packages first.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cache::{Cache, DEFAULT_TTL};
use crate::config::{FailOn, IgnoreRule, ScoreSection};
use crate::discovery::discover;
use crate::enrich::epss::{self, DEFAULT_EPSS_URL};
use crate::enrich::kev::{self, DEFAULT_KEV_URL};
use crate::enrich::merge_advisories;
use crate::error::CoreError;
use crate::http::HttpClient;
use crate::lockfile::parser_for;
use crate::model::{
    Advisory, BreakdownSignal, CvssSignal, Ecosystem, EpssSignal, Finding, FindingSignals,
    IgnoredItem, KevSignal, LockfileRecord, Package, Report, ReportContext, Summary, Tier,
    WeightSnapshot,
};
use crate::osv::{
    cache_query, cached_query, fetch_advisories_cached, query_batch, AdvisoryCache, OsvVulnRef,
};
use crate::score::{score_request, EpssSample, ScoreRequest};

/// Filters applied after parsing and before the OSV query.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// When false, the first lockfile that cannot be read or parsed fails the scan.
    pub keep_going: bool,
    /// Ecosystems to keep. `None` keeps every ecosystem.
    pub ecosystems: Option<Vec<Ecosystem>>,
    /// Drop packages the parser marked `dev`.
    pub no_dev: bool,
    /// Do not call the network. Queries and advisory bodies come from the cache.
    pub offline: bool,
    /// Do not read or write the cache.
    ///
    /// [`scan_path`] sets this so unit tests stay hermetic. The CLI turns it off
    /// unless the user passes `--no-cache`.
    pub no_cache: bool,
    /// SQLite file. Ignored when `no_cache` is set.
    pub cache_db: Option<PathBuf>,
    /// Unix seconds for TTL checks. `None` uses the current time.
    pub now: Option<i64>,
    /// Extra exclude globs from config and `--exclude`.
    pub excludes: Vec<String>,
    /// Fetch EPSS and KEV, then score. Library tests leave this off.
    pub enrich: bool,
    /// Threshold that sets [`Summary::failed`].
    pub fail_on: FailOn,
    /// Weights and tier cutoffs.
    pub score: ScoreSection,
    /// Advisory or CVE rules suppressed by config.
    pub ignore: Vec<IgnoreRule>,
    /// EPSS origin. The CLI sets this from `PATCHSENSE_EPSS_URL`.
    pub epss_base_url: String,
    /// KEV document URL. The CLI sets this from `PATCHSENSE_KEV_URL`.
    pub kev_feed_url: String,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            keep_going: true,
            ecosystems: None,
            no_dev: false,
            offline: false,
            no_cache: true,
            cache_db: None,
            now: None,
            excludes: Vec::new(),
            enrich: false,
            fail_on: FailOn::Critical,
            score: ScoreSection::default(),
            ignore: Vec::new(),
            epss_base_url: DEFAULT_EPSS_URL.to_string(),
            kev_feed_url: DEFAULT_KEV_URL.to_string(),
        }
    }
}

/// Discover lockfiles under `root`, parse them, and attach OSV advisories.
///
/// Uses [`ScanOptions::default`]: keep going, every ecosystem, include dev.
pub async fn scan_path<C>(client: &C, base_url: &str, root: &Path) -> Result<Report, CoreError>
where
    C: HttpClient + Clone + 'static,
{
    scan_with(client, base_url, root, &ScanOptions::default()).await
}

/// [`scan_path`] with explicit filters and keep-going behaviour.
pub async fn scan_with<C>(
    client: &C,
    base_url: &str,
    root: &Path,
    options: &ScanOptions,
) -> Result<Report, CoreError>
where
    C: HttpClient + Clone + 'static,
{
    let files = discover(root, &options.excludes)?;
    if files.is_empty() {
        return Err(CoreError::NoLockfile {
            path: root.to_path_buf(),
        });
    }

    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    let mut failures = Vec::new();
    let mut lockfiles = Vec::new();

    for file in &files {
        let label = source_label(root, file);
        let ecosystem = parser_for(file)
            .map(|parser| parser.ecosystem().as_osv_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let content = match std::fs::read_to_string(file) {
            Ok(content) => content,
            Err(source) => {
                let err = CoreError::Io {
                    path: file.clone(),
                    source,
                };
                if !options.keep_going {
                    return Err(err);
                }
                lockfiles.push(LockfileRecord {
                    path: label,
                    ecosystem,
                    packages: 0,
                    status: "error".to_string(),
                    warnings: vec![err.to_string()],
                });
                failures.push(err);
                continue;
            }
        };
        let parsed = match parser_for(file) {
            Some(parser) => parser.parse(file, &content),
            None => Err(CoreError::parse(
                file,
                None,
                "file is not a supported lockfile",
            )),
        };
        match parsed {
            Ok(parsed) => {
                let file_warnings = parsed.warnings.clone();
                warnings.extend(file_warnings.iter().cloned());
                lockfiles.push(LockfileRecord {
                    path: label.clone(),
                    ecosystem,
                    packages: parsed.packages.len(),
                    status: "ok".to_string(),
                    warnings: file_warnings,
                });
                let source = label;
                for mut package in parsed.packages {
                    package.source_file = source.clone();
                    package.source_files = vec![source.clone()];
                    packages.push(package);
                }
            }
            Err(err) => {
                if !options.keep_going {
                    return Err(err);
                }
                lockfiles.push(LockfileRecord {
                    path: label,
                    ecosystem,
                    packages: 0,
                    status: "error".to_string(),
                    warnings: vec![err.to_string()],
                });
                failures.push(err);
            }
        }
    }

    if !failures.is_empty() && failures.len() == files.len() {
        return Err(failures.swap_remove(0));
    }
    for err in failures {
        warnings.push(err.to_string());
    }

    packages.retain(|package| package_wanted(package, options));
    let packages = dedupe_packages(packages);

    let now = options.now.unwrap_or_else(unix_now);
    let cache = open_scan_cache(options)?;
    let matched = match_packages(
        client,
        base_url,
        &packages,
        options,
        cache.as_ref(),
        now,
        &mut warnings,
    )
    .await?;
    let mut groups = Vec::new();
    for (package, vulns) in packages.iter().zip(matched) {
        if vulns.is_empty() {
            continue;
        }
        let advisories = fetch_advisories_cached(
            client,
            base_url,
            &vulns,
            package,
            &AdvisoryCache {
                cache: cache.as_ref(),
                offline: options.offline,
                now,
                ttl: DEFAULT_TTL,
            },
            &mut warnings,
        )
        .await?;
        if !advisories.is_empty() {
            groups.push((package.clone(), advisories));
        }
    }
    let (findings, ignored, epss_date, kev_catalog_version) = if options.enrich {
        score_groups(client, options, cache.as_ref(), now, groups, &mut warnings).await?
    } else {
        let mut findings = Vec::new();
        for (package, advisories) in groups {
            for advisory in advisories {
                findings.push(Finding {
                    advisory,
                    package: package.clone(),
                    tier: Tier::Defer,
                    score: 0,
                    signals: FindingSignals::default(),
                });
            }
        }
        findings.sort_by(|left, right| {
            (
                &left.package.source_file,
                &left.package.name,
                &left.package.version,
                &left.advisory.id,
            )
                .cmp(&(
                    &right.package.source_file,
                    &right.package.name,
                    &right.package.version,
                    &right.advisory.id,
                ))
        });
        (findings, Vec::new(), None, None)
    };
    let summary = summarize(&findings, packages.len(), options);
    let generated_at = rfc3339_from_unix(now);

    Ok(Report {
        schema_version: 1,
        findings,
        warnings,
        summary,
        ignored,
        context: ReportContext {
            target: slash_path(root),
            generated_at: generated_at.clone(),
            lockfiles,
            osv_fetched_at: generated_at,
            osv_from_cache: options.offline,
            epss_date,
            epss_from_cache: false,
            kev_catalog_version,
            kev_from_cache: false,
            weights: WeightSnapshot {
                kev: options.score.weights.kev,
                epss: options.score.weights.epss,
                cvss: options.score.weights.cvss,
                direct: options.score.weights.direct,
                fix_available: options.score.weights.fix_available,
            },
            threshold_critical: options.score.thresholds.critical,
            threshold_review: options.score.thresholds.review,
            fail_on: fail_on_token(options.fail_on),
            explain_status: "not_requested".to_string(),
            explain_agent: None,
        },
    })
}

fn fail_on_token(fail_on: FailOn) -> String {
    match fail_on {
        FailOn::Critical => "critical".to_string(),
        FailOn::Review => "review".to_string(),
        FailOn::Any => "any".to_string(),
        FailOn::Never => "never".to_string(),
        FailOn::Score(score) => score.to_string(),
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp.
fn rfc3339_from_unix(seconds: i64) -> String {
    let date = crate::config::ymd_from_unix_seconds(seconds);
    let tod = seconds.rem_euclid(86_400) as u32;
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    format!("{date}T{hour:02}:{minute:02}:{second:02}Z")
}

async fn score_groups<C>(
    client: &C,
    options: &ScanOptions,
    cache: Option<&Cache>,
    now: i64,
    groups: Vec<(Package, Vec<Advisory>)>,
    warnings: &mut Vec<String>,
) -> Result<
    (
        Vec<Finding>,
        Vec<IgnoredItem>,
        Option<String>,
        Option<String>,
    ),
    CoreError,
>
where
    C: HttpClient + Clone + 'static,
{
    let cves = collect_cves(&groups);
    let (epss, kev, kev_catalog_version) = if cves.is_empty() {
        (BTreeMap::new(), BTreeMap::new(), None)
    } else if options.offline {
        warnings.push(
            "offline: EPSS and KEV were not fetched; missing rows count as absent".to_string(),
        );
        (BTreeMap::new(), BTreeMap::new(), None)
    } else {
        let epss = epss::fetch_epss(client, &options.epss_base_url, &cves, cache, now).await?;
        let catalog = kev::fetch_kev(client, &options.kev_feed_url, cache, now).await?;
        let version = catalog.catalog_version.clone();
        (epss, catalog.by_cve, Some(version))
    };
    let epss_date = epss.values().map(|entry| entry.date.clone()).max();

    let mut ranked = Vec::new();
    let mut ignored = Vec::new();
    let mut warned_weights = false;
    for (package, advisories) in &groups {
        for item in merge_advisories(advisories, &epss, &kev) {
            if let Some(rule) =
                matching_ignore(&item.id, &item.aliases, &item.cves, &options.ignore)
            {
                ignored.push(IgnoredItem {
                    id: item.id,
                    package: format!("{}@{}", package.name, package.version),
                    reason: rule.reason.clone(),
                    expires: rule.expires.clone(),
                });
                continue;
            }
            let Some(source) = advisories.iter().find(|advisory| advisory.id == item.id) else {
                continue;
            };
            let mut advisory = source.clone();
            advisory.aliases.clone_from(&item.aliases);
            advisory.references.clone_from(&item.references);
            advisory.fixed_versions.clone_from(&item.fixed_versions);
            let request = ScoreRequest {
                package_name: package.name.clone(),
                kev: item.kev,
                epss: item.epss.date.as_ref().map(|_| EpssSample {
                    score: item.epss.score,
                    percentile: item.epss.percentile,
                }),
                cvss_base: item.cvss.as_ref().map(|cvss| cvss.base_score),
                direct: package.direct,
                fix_available: !item.fixed_versions.is_empty(),
            };
            let (scored, score_warnings) = score_request(&request, &options.score);
            if !warned_weights {
                warnings.extend(score_warnings);
                warned_weights = true;
            }
            ranked.push((
                item.kev,
                Finding {
                    advisory,
                    package: package.clone(),
                    tier: scored.tier,
                    score: scored.score,
                    signals: signals_from(&item, &scored.breakdown),
                },
            ));
        }
    }
    ranked.sort_by(|left, right| {
        right
            .1
            .score
            .cmp(&left.1.score)
            .then_with(|| right.0.cmp(&left.0))
            .then_with(|| left.1.package.name.cmp(&right.1.package.name))
            .then_with(|| left.1.advisory.id.cmp(&right.1.advisory.id))
    });
    let findings = ranked.into_iter().map(|(_, finding)| finding).collect();
    Ok((findings, ignored, epss_date, kev_catalog_version))
}

fn signals_from(
    item: &crate::enrich::EnrichedAdvisory,
    breakdown: &crate::score::ScoreBreakdown,
) -> FindingSignals {
    FindingSignals {
        cves: item.cves.clone(),
        cvss: item.cvss.as_ref().map(|cvss| CvssSignal {
            version: cvss.version.clone(),
            vector: cvss.vector.clone(),
            base_score: cvss.base_score,
            source: cvss.source.as_str().to_string(),
        }),
        epss: item.epss.date.as_ref().map(|date| EpssSignal {
            score: item.epss.score,
            percentile: item.epss.percentile,
            date: date.clone(),
        }),
        kev: item.kev_record.as_ref().map(|kev| KevSignal {
            date_added: kev.date_added.clone(),
            due_date: kev.due_date.clone(),
            ransomware: kev.known_ransomware_campaign_use.clone(),
            name: kev.vulnerability_name.clone(),
        }),
        breakdown: Some(BreakdownSignal {
            kev: breakdown.kev,
            epss: breakdown.epss,
            cvss: breakdown.cvss,
            direct: breakdown.direct,
            fix_available: breakdown.fix_available,
            total_weight: breakdown.total_weight,
        }),
        explanation: None,
    }
}

fn collect_cves(groups: &[(Package, Vec<Advisory>)]) -> Vec<String> {
    let mut cves = BTreeSet::new();
    for (_, advisories) in groups {
        for advisory in advisories {
            if is_cve(&advisory.id) {
                cves.insert(advisory.id.to_ascii_uppercase());
            }
            for alias in &advisory.aliases {
                if is_cve(alias) {
                    cves.insert(alias.to_ascii_uppercase());
                }
            }
        }
    }
    cves.into_iter().collect()
}

fn is_cve(id: &str) -> bool {
    id.len() >= 4 && id[..4].eq_ignore_ascii_case("CVE-")
}

fn matching_ignore<'a>(
    id: &str,
    aliases: &[String],
    cves: &[String],
    rules: &'a [IgnoreRule],
) -> Option<&'a IgnoreRule> {
    rules.iter().find(|rule| {
        rule.id == id
            || aliases.iter().any(|alias| alias == &rule.id)
            || cves.iter().any(|cve| cve.eq_ignore_ascii_case(&rule.id))
    })
}

fn summarize(findings: &[Finding], packages_scanned: usize, options: &ScanOptions) -> Summary {
    let mut summary = Summary {
        packages_scanned,
        findings: findings.len(),
        critical: findings
            .iter()
            .filter(|finding| finding.tier == Tier::Critical)
            .count(),
        review: findings
            .iter()
            .filter(|finding| finding.tier == Tier::Review)
            .count(),
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
    };
    summary.failed = findings
        .iter()
        .any(|finding| meets_fail_on(finding.score, options.fail_on, &options.score.thresholds));
    summary
}

fn meets_fail_on(score: u32, fail_on: FailOn, thresholds: &crate::config::Thresholds) -> bool {
    match fail_on {
        FailOn::Never => false,
        FailOn::Any => true,
        FailOn::Critical => f64::from(score) >= thresholds.critical,
        FailOn::Review => f64::from(score) >= thresholds.review,
        FailOn::Score(limit) => score >= u32::from(limit),
    }
}

fn open_scan_cache(options: &ScanOptions) -> Result<Option<Cache>, CoreError> {
    if options.no_cache {
        return Ok(None);
    }
    let Some(path) = &options.cache_db else {
        return Ok(None);
    };
    Ok(Some(Cache::open(path)?))
}

async fn match_packages<C>(
    client: &C,
    base_url: &str,
    packages: &[Package],
    options: &ScanOptions,
    cache: Option<&Cache>,
    now: i64,
    warnings: &mut Vec<String>,
) -> Result<Vec<Vec<OsvVulnRef>>, CoreError>
where
    C: HttpClient + Clone + 'static,
{
    if options.offline {
        let mut matched = Vec::with_capacity(packages.len());
        for package in packages {
            let refs = match cache {
                Some(cache) => cached_query(cache, package, now, DEFAULT_TTL)?,
                None => None,
            };
            match refs {
                Some(refs) => matched.push(refs),
                None => {
                    warnings.push(format!(
                        "offline: no cached OSV query for {} {}@{}",
                        package.ecosystem.as_osv_str(),
                        package.name,
                        package.version
                    ));
                    matched.push(Vec::new());
                }
            }
        }
        return Ok(matched);
    }
    let matched = query_batch(client, base_url, packages).await?;
    if let Some(cache) = cache {
        for (package, vulns) in packages.iter().zip(&matched) {
            cache_query(cache, package, vulns, now)?;
        }
    }
    Ok(matched)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn package_wanted(package: &Package, options: &ScanOptions) -> bool {
    if options.no_dev && package.dev {
        return false;
    }
    if let Some(ecosystems) = &options.ecosystems {
        return ecosystems.contains(&package.ecosystem);
    }
    true
}

/// Merge packages that share ecosystem, name, and version.
///
/// `source_files` keeps every lockfile, sorted. `direct` is `Some(true)` when
/// any copy is direct, otherwise `Some(false)` when any copy knows, otherwise
/// `None`. `dev` stays true only when every copy is dev, so a production
/// occurrence is not hidden by `--no-dev`.
fn dedupe_packages(packages: Vec<Package>) -> Vec<Package> {
    let mut merged: BTreeMap<(Ecosystem, String, String), Package> = BTreeMap::new();
    for package in packages {
        let key = (
            package.ecosystem,
            package.name.clone(),
            package.version.clone(),
        );
        match merged.get_mut(&key) {
            Some(existing) => merge_package(existing, package),
            None => {
                merged.insert(key, package);
            }
        }
    }
    let mut packages: Vec<Package> = merged.into_values().collect();
    packages.sort_by(|left, right| {
        (&left.source_file, &left.name, &left.version).cmp(&(
            &right.source_file,
            &right.name,
            &right.version,
        ))
    });
    packages
}

fn merge_package(existing: &mut Package, incoming: Package) {
    let mut files = existing.source_files.clone();
    for file in incoming.source_files {
        if !files.contains(&file) {
            files.push(file);
        }
    }
    files.sort();
    existing.source_files = files;
    existing.source_file = existing.source_files.join(", ");
    existing.direct = merge_direct(existing.direct, incoming.direct);
    existing.dev = existing.dev && incoming.dev;
    if existing.line.is_none() {
        existing.line = incoming.line;
    }
}

fn merge_direct(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        (None, None) => None,
    }
}

fn source_label(root: &Path, file: &Path) -> String {
    if root.is_file() {
        return file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| slash_path(file));
    }
    file.strip_prefix(root)
        .map(slash_path)
        .unwrap_or_else(|_| slash_path(file))
}

fn slash_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{FakeHttp, HttpResponse, RecordedRequest};
    use serde_json::{json, Value};
    use std::fs;

    fn lodash_advisory() -> String {
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
            }],
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
                }]
            }]
        })
        .to_string()
    }

    fn fake_osv() -> FakeHttp {
        let advisory = lodash_advisory();
        FakeHttp::with_handler(move |request: &RecordedRequest| {
            if request.method == "POST" && request.url.ends_with("/v1/querybatch") {
                let body: Value = serde_json::from_str(&request.body).expect("query json");
                let queries = body["queries"].as_array().expect("queries");
                let results: Vec<Value> = queries
                    .iter()
                    .map(|query| {
                        if query["package"]["name"] == "lodash" {
                            json!({"vulns": [{
                                "id": "GHSA-35jh-r3h4-6jhm",
                                "modified": "2024-01-01T00:00:00Z"
                            }]})
                        } else {
                            json!({})
                        }
                    })
                    .collect();
                return HttpResponse {
                    status: 200,
                    body: json!({"results": results}).to_string(),
                };
            }
            if request.method == "GET" && request.url.ends_with("/v1/vulns/GHSA-35jh-r3h4-6jhm") {
                return HttpResponse {
                    status: 200,
                    body: advisory.clone(),
                };
            }
            HttpResponse {
                status: 404,
                body: format!("unexpected {}", request.url),
            }
        })
    }

    #[tokio::test]
    async fn empty_directory_does_not_call_osv() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = scan_path(&FakeHttp::forbid(), "https://api.osv.dev", dir.path())
            .await
            .expect_err("missing lockfile");
        assert!(matches!(err, CoreError::NoLockfile { .. }), "{err}");
    }

    #[tokio::test]
    async fn lodash_lockfile_becomes_a_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = r#"{
            "name": "demo",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": { "version": "4.17.14" },
                "left-pad": { "version": "1.3.0" }
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), lock).expect("write");
        let report = scan_path(&fake_osv(), "https://api.osv.dev", dir.path())
            .await
            .expect("scan");
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.package.name, "lodash");
        assert_eq!(finding.package.version, "4.17.14");
        assert_eq!(finding.package.source_file, "package-lock.json");
        assert_eq!(finding.advisory.id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(finding.advisory.aliases, vec!["CVE-2021-23337".to_string()]);
        assert_eq!(finding.advisory.fixed_versions, vec!["4.17.21".to_string()]);
        assert_eq!(finding.tier, Tier::Defer);
    }

    const LODASH_V1: &str = r#"{
        "name": "demo",
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": { "version": "4.17.14" }
        }
    }"#;

    #[tokio::test]
    async fn one_broken_lockfile_warns_and_scan_continues() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("a-bad")).expect("dir");
        fs::create_dir(dir.path().join("b-good")).expect("dir");
        fs::write(dir.path().join("a-bad/package-lock.json"), "{").expect("bad");
        fs::write(dir.path().join("b-good/package-lock.json"), LODASH_V1).expect("good");
        let http = fake_osv();
        let report = scan_path(&http, "https://api.osv.dev", dir.path())
            .await
            .expect("scan");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].package.source_file,
            "b-good/package-lock.json"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("a-bad/package-lock.json")),
            "{:?}",
            report.warnings
        );
    }

    #[tokio::test]
    async fn every_lockfile_failing_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("a")).expect("dir");
        fs::create_dir(dir.path().join("b")).expect("dir");
        fs::write(dir.path().join("a/package-lock.json"), "{").expect("bad");
        fs::write(dir.path().join("b/package-lock.json"), "[]").expect("bad");
        let err = scan_path(&FakeHttp::forbid(), "https://api.osv.dev", dir.path())
            .await
            .expect_err("all broken");
        let message = err.to_string();
        assert!(message.contains("package-lock.json"), "{message}");
    }

    #[tokio::test]
    async fn no_keep_going_stops_on_the_first_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("a-bad")).expect("dir");
        fs::create_dir(dir.path().join("b-good")).expect("dir");
        fs::write(dir.path().join("a-bad/package-lock.json"), "{").expect("bad");
        fs::write(dir.path().join("b-good/package-lock.json"), LODASH_V1).expect("good");
        let options = ScanOptions {
            keep_going: false,
            ..ScanOptions::default()
        };
        let err = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &options,
        )
        .await
        .expect_err("stop");
        assert!(err.to_string().contains("a-bad/package-lock.json"), "{err}");
    }

    #[tokio::test]
    async fn duplicate_packages_are_queried_once_and_keep_every_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("a")).expect("dir");
        fs::create_dir(dir.path().join("b")).expect("dir");
        fs::write(dir.path().join("a/package-lock.json"), LODASH_V1).expect("a");
        fs::write(dir.path().join("b/package-lock.json"), LODASH_V1).expect("b");
        let http = fake_osv();
        let report = scan_path(&http, "https://api.osv.dev", dir.path())
            .await
            .expect("scan");
        let post = http
            .recorded()
            .into_iter()
            .find(|request| request.method == "POST")
            .expect("query");
        let body: Value = serde_json::from_str(&post.body).expect("json");
        assert_eq!(body["queries"].as_array().expect("queries").len(), 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].package.source_files,
            vec![
                "a/package-lock.json".to_string(),
                "b/package-lock.json".to_string()
            ]
        );
        assert_eq!(
            report.findings[0].package.source_file,
            "a/package-lock.json, b/package-lock.json"
        );
    }

    #[tokio::test]
    async fn ecosystem_and_no_dev_filters_run_before_osv() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{
                "name": "demo",
                "lockfileVersion": 1,
                "dependencies": {
                    "lodash": { "version": "4.17.14", "dev": true },
                    "left-pad": { "version": "1.3.0" }
                }
            }"#,
        )
        .expect("lock");
        fs::write(dir.path().join("requirements.txt"), "requests==2.32.3\n").expect("req");

        let npm_only = ScanOptions {
            ecosystems: Some(vec![Ecosystem::Npm]),
            no_dev: true,
            ..ScanOptions::default()
        };
        let http = fake_osv();
        let report = scan_with(&http, "https://api.osv.dev", dir.path(), &npm_only)
            .await
            .expect("scan");
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        let post = http
            .recorded()
            .into_iter()
            .find(|request| request.method == "POST")
            .expect("query");
        assert!(post.body.contains("left-pad"), "{}", post.body);
        assert!(!post.body.contains("lodash"), "{}", post.body);
        assert!(!post.body.contains("requests"), "{}", post.body);

        let pypi = ScanOptions {
            ecosystems: Some(vec![Ecosystem::Pypi]),
            ..ScanOptions::default()
        };
        let http = fake_osv();
        let report = scan_with(&http, "https://api.osv.dev", dir.path(), &pypi)
            .await
            .expect("scan");
        assert!(report.findings.is_empty());
        let post = http
            .recorded()
            .into_iter()
            .find(|request| request.method == "POST")
            .expect("query");
        assert!(post.body.contains("requests"), "{}", post.body);
        assert!(!post.body.contains("lodash"), "{}", post.body);
    }

    fn lodash_options(dir: &Path, now: i64) -> ScanOptions {
        ScanOptions {
            no_cache: false,
            cache_db: Some(dir.join("cache.db")),
            now: Some(now),
            ..ScanOptions::default()
        }
    }

    #[tokio::test]
    async fn second_scan_does_not_fetch_advisory_bodies() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
        )
        .expect("lock");
        let options = lodash_options(dir.path(), 1_700_000_000);
        let first = fake_osv();
        let report = scan_with(&first, "https://api.osv.dev", dir.path(), &options)
            .await
            .expect("first");
        assert_eq!(report.findings.len(), 1);
        assert!(
            first
                .recorded()
                .iter()
                .any(|request| request.url.contains("/v1/vulns/")),
            "first scan should fetch the advisory"
        );

        let second = fake_osv();
        let report = scan_with(&second, "https://api.osv.dev", dir.path(), &options)
            .await
            .expect("second");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].advisory.id, "GHSA-35jh-r3h4-6jhm");
        assert!(
            second
                .recorded()
                .iter()
                .all(|request| !request.url.contains("/v1/vulns/")),
            "second scan fetched {:?}",
            second
                .recorded()
                .iter()
                .map(|request| request.url.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            second
                .recorded()
                .iter()
                .any(|request| request.url.contains("/v1/querybatch")),
            "querybatch is not cached away from the network in online mode"
        );
    }

    #[tokio::test]
    async fn offline_scan_does_not_call_http() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
        )
        .expect("lock");
        let mut options = lodash_options(dir.path(), 1_700_000_000);
        options.offline = true;
        let report = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &options,
        )
        .await
        .expect("offline");
        assert!(report.findings.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("offline:")),
            "{:?}",
            report.warnings
        );
    }
}
