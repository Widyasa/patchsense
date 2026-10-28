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
//! `--offline` reads OSV, EPSS, and KEV from the cache. A missing or expired
//! OSV query or advisory is an error. A missing EPSS or KEV row is a warning.
//! An expired EPSS or KEV row is still used, with a warning that names its
//! age, unless `strict_cache` is set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cache::{Cache, DEFAULT_TTL};
use crate::config::{FailOn, IgnoreRule, ScoreSection};
use crate::discovery::discover_report;
use crate::enrich::epss::{self, DEFAULT_EPSS_URL};
use crate::enrich::kev::{self, DEFAULT_KEV_URL};
use crate::enrich::merge_advisories;
use crate::error::CoreError;
use crate::go_imports::{self, GoImportFilter};
use crate::http::HttpClient;
use crate::lockfile::parser_for;
use crate::model::{
    Advisory, BreakdownSignal, CvssSignal, Ecosystem, EpssSignal, Finding, FindingSignals,
    IgnoredItem, KevSignal, LockfileRecord, Package, Report, ReportContext, Summary, Tier,
    WeightSnapshot,
};
use crate::osv::{
    cache_query, cached_query, fetch_advisories_cached, query_batch, AdvisoryCache, FetchOrigin,
    OsvVulnRef,
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
    /// Directories and test files the Go import check ignores.
    pub go_imports: GoImportFilter,
    /// How long a cached OSV query or advisory stays fresh.
    pub ttl_osv: Duration,
    /// How long a cached EPSS row stays fresh.
    pub ttl_epss: Duration,
    /// How long a cached KEV catalog stays fresh.
    pub ttl_kev: Duration,
    /// `--offline` fails when an EPSS row or the KEV catalog is expired.
    pub strict_cache: bool,
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
            go_imports: GoImportFilter::default(),
            ttl_osv: DEFAULT_TTL,
            ttl_epss: DEFAULT_TTL,
            ttl_kev: DEFAULT_TTL,
            strict_cache: false,
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
    let discovered = discover_report(root, &options.excludes)?;
    let files = discovered.files;
    if files.is_empty() {
        let hint = if discovered.warnings.is_empty() {
            String::new()
        } else {
            format!(". {}", discovered.warnings.join(". "))
        };
        return Err(CoreError::NoLockfile {
            path: root.to_path_buf(),
            hint,
        });
    }

    let mut packages = Vec::new();
    let mut warnings = discovered.warnings;
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
                let kept = parsed
                    .packages
                    .iter()
                    .filter(|package| package_wanted(package, options))
                    .count();
                lockfiles.push(LockfileRecord {
                    path: label.clone(),
                    ecosystem,
                    packages: kept,
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
    let (matched, mut osv_origin) =
        match_packages(client, base_url, &packages, options, cache.as_ref(), now).await?;
    let mut groups = Vec::new();
    for (package, vulns) in packages.iter().zip(matched) {
        if vulns.is_empty() {
            continue;
        }
        let (advisories, body_origin) = fetch_advisories_cached(
            client,
            base_url,
            &vulns,
            package,
            &AdvisoryCache {
                cache: cache.as_ref(),
                offline: options.offline,
                now,
                ttl: options.ttl_osv,
            },
        )
        .await?;
        osv_origin.merge(&body_origin);
        if !advisories.is_empty() {
            groups.push((package.clone(), advisories));
        }
    }
    let scored = if options.enrich {
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
                    import_note: None,
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
        ScoredScan {
            findings,
            ignored: Vec::new(),
            epss_date: None,
            kev_catalog_version: None,
            epss_from_cache: false,
            kev_from_cache: false,
        }
    };
    let mut findings = scored.findings;
    go_imports::annotate_findings(&mut findings, root, &options.go_imports, &mut warnings);
    let summary = summarize(&findings, packages.len(), options);
    let generated_at = rfc3339_from_unix(now);

    Ok(Report {
        schema_version: 1,
        findings,
        warnings,
        summary,
        ignored: scored.ignored,
        context: ReportContext {
            target: slash_path(root),
            generated_at,
            lockfiles,
            osv_fetched_at: rfc3339_from_unix(osv_origin.fetched_at(now)),
            osv_from_cache: osv_origin.served_from_cache(),
            epss_date: scored.epss_date,
            epss_from_cache: scored.epss_from_cache,
            kev_catalog_version: scored.kev_catalog_version,
            kev_from_cache: scored.kev_from_cache,
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

struct ScoredScan {
    findings: Vec<Finding>,
    ignored: Vec<IgnoredItem>,
    epss_date: Option<String>,
    kev_catalog_version: Option<String>,
    epss_from_cache: bool,
    kev_from_cache: bool,
}

async fn score_groups<C>(
    client: &C,
    options: &ScanOptions,
    cache: Option<&Cache>,
    now: i64,
    groups: Vec<(Package, Vec<Advisory>)>,
    warnings: &mut Vec<String>,
) -> Result<ScoredScan, CoreError>
where
    C: HttpClient + Clone + 'static,
{
    let cves = collect_cves(&groups);
    let (epss, kev, kev_catalog_version, epss_from_cache, kev_from_cache) = if cves.is_empty() {
        (BTreeMap::new(), BTreeMap::new(), None, false, false)
    } else {
        load_enrichment(client, options, cache, now, &cves, warnings).await?
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
                    import_note: None,
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
    Ok(ScoredScan {
        findings,
        ignored,
        epss_date,
        kev_catalog_version,
        epss_from_cache,
        kev_from_cache,
    })
}

async fn load_enrichment<C>(
    client: &C,
    options: &ScanOptions,
    cache: Option<&Cache>,
    now: i64,
    cves: &[String],
    warnings: &mut Vec<String>,
) -> Result<
    (
        BTreeMap<String, crate::cache::EpssEntry>,
        BTreeMap<String, kev::KevRecord>,
        Option<String>,
        bool,
        bool,
    ),
    CoreError,
>
where
    C: HttpClient + Clone + 'static,
{
    let mut epss = BTreeMap::new();
    let mut missing_epss = Vec::new();
    let mut stale_epss = Vec::new();
    let mut strict_notes = Vec::new();
    if let Some(cache) = cache {
        for cve in cves {
            if let Some(entry) = cache.get_epss(cve, now, options.ttl_epss)? {
                epss.insert(cve.clone(), entry);
                continue;
            }
            if let Some(entry) = cache.get_epss_stored(cve)? {
                let age = now.saturating_sub(entry.fetched_at).max(0);
                if options.offline && options.strict_cache {
                    strict_notes.push(format!(
                        "EPSS for {cve} is {} old, past the {} TTL",
                        format_span(age),
                        format_span(secs(options.ttl_epss))
                    ));
                } else if options.offline {
                    stale_epss.push((cve.clone(), age));
                    epss.insert(cve.clone(), entry);
                } else {
                    missing_epss.push(cve.clone());
                }
                continue;
            }
            missing_epss.push(cve.clone());
        }
    } else {
        missing_epss = cves.to_vec();
    }

    let (kev, kev_catalog_version, kev_from_cache) = if let Some(cache) = cache {
        if let Some(entry) = cache.get_kev(now, options.ttl_kev)? {
            let catalog = kev::parse_kev_catalog(&entry.json)?;
            let version = catalog.catalog_version.clone();
            (catalog.by_cve, Some(version), true)
        } else if let Some(entry) = cache.get_kev_stored()? {
            let age = now.saturating_sub(entry.fetched_at).max(0);
            if options.offline && options.strict_cache {
                strict_notes.push(format!(
                    "KEV catalog {} is {} old, past the {} TTL",
                    entry.catalog_version,
                    format_span(age),
                    format_span(secs(options.ttl_kev))
                ));
                (BTreeMap::new(), None, false)
            } else if options.offline {
                let catalog = kev::parse_kev_catalog(&entry.json)?;
                warnings.push(format!(
                    "offline: cached KEV catalog {} is {} old, past the {} TTL; using the stale catalog",
                    catalog.catalog_version,
                    format_span(age),
                    format_span(secs(options.ttl_kev))
                ));
                let version = catalog.catalog_version.clone();
                (catalog.by_cve, Some(version), true)
            } else {
                let catalog = kev::fetch_kev_ttl(
                    client,
                    &options.kev_feed_url,
                    Some(cache),
                    now,
                    options.ttl_kev,
                )
                .await?;
                let version = catalog.catalog_version.clone();
                (catalog.by_cve, Some(version), false)
            }
        } else if options.offline {
            warnings.push(
                "offline: the KEV catalog is not in the cache; KEV counts as absent".to_string(),
            );
            (BTreeMap::new(), None, false)
        } else {
            let catalog = kev::fetch_kev_ttl(
                client,
                &options.kev_feed_url,
                Some(cache),
                now,
                options.ttl_kev,
            )
            .await?;
            let version = catalog.catalog_version.clone();
            (catalog.by_cve, Some(version), false)
        }
    } else if options.offline {
        warnings
            .push("offline: the KEV catalog is not in the cache; KEV counts as absent".to_string());
        (BTreeMap::new(), None, false)
    } else {
        let catalog =
            kev::fetch_kev_ttl(client, &options.kev_feed_url, None, now, options.ttl_kev).await?;
        let version = catalog.catalog_version.clone();
        (catalog.by_cve, Some(version), false)
    };

    if !strict_notes.is_empty() {
        return Err(CoreError::OfflineCache {
            message: format!(
                "offline cache is stale: {}. Run without --offline to refresh, or omit --strict-cache to use the stale rows",
                strict_notes.join("; ")
            ),
        });
    }
    if !stale_epss.is_empty() {
        stale_epss.sort_by_key(|(_, age)| std::cmp::Reverse(*age));
        let (cve, age) = &stale_epss[0];
        let note = if stale_epss.len() == 1 {
            format!(
                "offline: cached EPSS for {cve} is {} old, past the {} TTL; using the stale score",
                format_span(*age),
                format_span(secs(options.ttl_epss))
            )
        } else {
            format!(
                "offline: cached EPSS for {} CVEs is stale (oldest {cve} is {} old, TTL {}); using the stale scores",
                stale_epss.len(),
                format_span(*age),
                format_span(secs(options.ttl_epss))
            )
        };
        warnings.push(note);
    }

    let epss_from_cache = missing_epss.is_empty();
    if !missing_epss.is_empty() {
        if options.offline {
            warnings.push(format!(
                "offline: EPSS has no cached row for {} CVE(s), including {}; those scores count as absent",
                missing_epss.len(),
                missing_epss[0]
            ));
        } else {
            let fetched = epss::fetch_epss_ttl(
                client,
                &options.epss_base_url,
                &missing_epss,
                cache,
                now,
                options.ttl_epss,
            )
            .await?;
            epss.extend(fetched);
        }
    }
    Ok((
        epss,
        kev,
        kev_catalog_version,
        epss_from_cache,
        kev_from_cache,
    ))
}

fn secs(ttl: Duration) -> i64 {
    i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX)
}

fn format_span(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 && minutes > 0 {
        format!("{hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
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
) -> Result<(Vec<Vec<OsvVulnRef>>, FetchOrigin), CoreError>
where
    C: HttpClient + Clone + 'static,
{
    let mut matched = vec![Vec::new(); packages.len()];
    let mut origin = FetchOrigin::default();
    let mut misses = Vec::new();
    let mut missing = Vec::new();
    for (index, package) in packages.iter().enumerate() {
        if let Some(cache) = cache {
            if let Some(hit) = cached_query(cache, package, now, options.ttl_osv)? {
                origin.note_cache(hit.fetched_at);
                matched[index] = hit.vulns;
                continue;
            }
        }
        if options.offline {
            missing.push(format!(
                "{} {}@{}",
                package.ecosystem.as_osv_str(),
                package.name,
                package.version
            ));
        } else {
            misses.push(index);
        }
    }
    if !missing.is_empty() {
        return Err(CoreError::OfflineCache {
            message: format!(
                "offline cache is missing OSV results for {} package(s), including {}. Run a scan without --offline to fill the cache",
                missing.len(),
                missing[0]
            ),
        });
    }
    if !misses.is_empty() {
        origin.note_network();
        let pending = misses
            .iter()
            .map(|index| packages[*index].clone())
            .collect::<Vec<_>>();
        let queried = query_batch(client, base_url, &pending).await?;
        if let Some(cache) = cache {
            for (package, vulns) in pending.iter().zip(&queried) {
                cache_query(cache, package, vulns, now)?;
            }
        }
        for (index, vulns) in misses.into_iter().zip(queried) {
            matched[index] = vulns;
        }
    }
    Ok((matched, origin))
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

/// Smallest version that is at least every advisory's lowest fixed version.
///
/// Each inner list is one advisory. The floor of a list is its lowest semver
/// entry (`v` prefixes are accepted). The result is the highest of those
/// floors, returned with the spelling it had in the input. `None` when any
/// advisory has no parseable fixed version, because no single upgrade is known
/// to close that advisory.
pub fn minimum_covering_fix(fixed_lists: &[Vec<String>]) -> Option<String> {
    if fixed_lists.is_empty() {
        return None;
    }
    let mut floors = Vec::with_capacity(fixed_lists.len());
    for list in fixed_lists {
        let mut parsed: Vec<(semver::Version, String)> = list
            .iter()
            .filter_map(|raw| parse_fix_version(raw).map(|version| (version, raw.clone())))
            .collect();
        if parsed.is_empty() {
            return None;
        }
        parsed.sort_by(|left, right| left.0.cmp(&right.0));
        floors.push(parsed.remove(0));
    }
    floors
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, raw)| raw)
}

fn parse_fix_version(value: &str) -> Option<semver::Version> {
    let trimmed = value.trim().trim_start_matches('v');
    if trimmed.is_empty() {
        return None;
    }
    semver::Version::parse(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::http::{FakeHttp, HttpResponse, RecordedRequest};
    use crate::model::{Finding, Report};
    use serde_json::{json, Value};
    use std::fs;
    use std::path::PathBuf;

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
    async fn requirements_variants_are_scanned_including_an_explicit_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("workers/chatbot")).expect("dir");
        fs::create_dir_all(dir.path().join("requirements")).expect("dir");
        let rag = dir.path().join("workers/chatbot/requirements-rag.txt");
        fs::write(&rag, "requests==2.32.3\n").expect("rag");
        fs::write(dir.path().join("requirements/base.txt"), "flask==3.0.3\n").expect("base");
        fs::write(dir.path().join("notes.txt"), "requests==1.0.0\n").expect("notes");

        let report = scan_path(&fake_osv(), "https://api.osv.dev", dir.path())
            .await
            .expect("directory scan");
        let mut paths: Vec<&str> = report
            .context
            .lockfiles
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "requirements/base.txt",
                "workers/chatbot/requirements-rag.txt",
            ]
        );
        assert!(report
            .context
            .lockfiles
            .iter()
            .all(|file| file.status == "ok" && file.ecosystem == "PyPI"));
        assert_eq!(report.findings.len(), 0);

        let explicit = scan_path(&fake_osv(), "https://api.osv.dev", &rag)
            .await
            .expect("explicit file");
        assert_eq!(explicit.context.lockfiles.len(), 1);
        assert_eq!(explicit.context.lockfiles[0].path, "requirements-rag.txt");
        assert_eq!(explicit.context.lockfiles[0].status, "ok");
        assert_eq!(explicit.context.lockfiles[0].packages, 1);
        assert_eq!(explicit.context.lockfiles[0].ecosystem, "PyPI");
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
        assert!(!report.context.osv_from_cache);

        let second = fake_osv();
        let mut later = options.clone();
        later.now = Some(1_700_000_060);
        let report = scan_with(&second, "https://api.osv.dev", dir.path(), &later)
            .await
            .expect("second");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].advisory.id, "GHSA-35jh-r3h4-6jhm");
        assert!(
            second.recorded().is_empty(),
            "second scan fetched {:?}",
            second
                .recorded()
                .iter()
                .map(|request| request.url.clone())
                .collect::<Vec<_>>()
        );
        assert!(report.context.osv_from_cache);
        assert_eq!(
            report.context.osv_fetched_at,
            rfc3339_from_unix(1_700_000_000)
        );
        assert_ne!(report.context.osv_fetched_at, report.context.generated_at);
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
        let err = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &options,
        )
        .await
        .expect_err("cold offline cache");
        let message = err.to_string();
        assert!(
            message.contains("offline cache is missing OSV results"),
            "{message}"
        );
        assert!(message.contains("lodash@4.17.14"), "{message}");
    }

    #[tokio::test]
    async fn warm_offline_score_matches_online() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
        )
        .expect("lock");
        let advisory = lodash_advisory();
        let http = FakeHttp::with_handler(move |request: &RecordedRequest| {
            if request.method == "POST" && request.url.ends_with("/v1/querybatch") {
                return HttpResponse {
                    status: 200,
                    body: json!({"results":[{"vulns":[{
                        "id": "GHSA-35jh-r3h4-6jhm",
                        "modified": "2024-01-01T00:00:00Z"
                    }]}]})
                    .to_string(),
                };
            }
            if request.url.contains("/v1/vulns/") {
                return HttpResponse {
                    status: 200,
                    body: advisory.clone(),
                };
            }
            if request.url.contains("/data/v1/epss") {
                return HttpResponse {
                    status: 200,
                    body: r#"{"data":[{"cve":"CVE-2021-23337","epss":"0.21333","percentile":"0.95","date":"2026-10-24"}]}"#.to_string(),
                };
            }
            if request.url.contains("known_exploited") {
                return HttpResponse {
                    status: 200,
                    body: r#"{"catalogVersion":"2026.10.24","vulnerabilities":[{"cveID":"CVE-2021-23337","dateAdded":"2026-01-01","dueDate":"2026-02-01","knownRansomwareCampaignUse":"Unknown","vulnerabilityName":"lodash","requiredAction":"apply updates"}]}"#.to_string(),
                };
            }
            HttpResponse {
                status: 500,
                body: format!("unexpected {}", request.url),
            }
        });
        let mut online = lodash_options(dir.path(), 1_700_000_000);
        online.enrich = true;
        let first = scan_with(&http, "https://api.osv.dev", dir.path(), &online)
            .await
            .expect("online");
        assert!(!first.context.osv_from_cache);
        assert!(!first.context.epss_from_cache);
        assert!(!first.context.kev_from_cache);
        assert!(first.findings[0].signals.kev.is_some());

        let mut offline = online.clone();
        offline.offline = true;
        offline.now = Some(1_700_000_100);
        let second = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &offline,
        )
        .await
        .expect("warm offline");
        assert_eq!(second.findings[0].score, first.findings[0].score);
        assert_eq!(second.findings[0].tier, first.findings[0].tier);
        assert!(second.findings[0].signals.kev.is_some());
        assert!(
            second.findings[0].score > 40,
            "KEV should raise the score, got {}",
            second.findings[0].score
        );
        assert!(second.context.osv_from_cache);
        assert!(second.context.epss_from_cache);
        assert!(second.context.kev_from_cache);
        assert_eq!(second.context.osv_fetched_at, first.context.osv_fetched_at);
        assert_ne!(second.context.osv_fetched_at, second.context.generated_at);
        assert_eq!(second.context.epss_date.as_deref(), Some("2026-10-24"));
        assert_eq!(
            second.context.kev_catalog_version.as_deref(),
            Some("2026.10.24")
        );
        let json = crate::report::render_json(&second).expect("json");
        let value: Value = serde_json::from_str(&json).expect("json value");
        assert_eq!(value["data_sources"]["osv"]["from_cache"], true);
        assert_eq!(value["data_sources"]["epss"]["from_cache"], true);
        assert_eq!(value["data_sources"]["kev"]["from_cache"], true);
        assert_eq!(
            value["data_sources"]["osv"]["fetched_at"],
            first.context.osv_fetched_at
        );
    }

    #[tokio::test]
    async fn osv_ttl_of_one_hour_rejects_a_two_hour_old_offline_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
        )
        .expect("lock");
        let mut options = lodash_options(dir.path(), 1_700_000_000);
        scan_with(&fake_osv(), "https://api.osv.dev", dir.path(), &options)
            .await
            .expect("warm");
        options.offline = true;
        options.ttl_osv = Duration::from_secs(3_600);
        options.now = Some(1_700_000_000 + 7_200);
        let err = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &options,
        )
        .await
        .expect_err("expired osv");
        let message = err.to_string();
        assert!(message.contains("offline cache"), "{message}");
        assert!(message.contains("lodash@4.17.14"), "{message}");
    }

    #[tokio::test]
    async fn stale_offline_kev_keeps_the_score_unless_strict() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
        )
        .expect("lock");
        let advisory = lodash_advisory();
        let http = FakeHttp::with_handler(move |request: &RecordedRequest| {
            if request.method == "POST" && request.url.ends_with("/v1/querybatch") {
                return HttpResponse {
                    status: 200,
                    body: json!({"results":[{"vulns":[{
                        "id": "GHSA-35jh-r3h4-6jhm",
                        "modified": "2024-01-01T00:00:00Z"
                    }]}]})
                    .to_string(),
                };
            }
            if request.url.contains("/v1/vulns/") {
                return HttpResponse {
                    status: 200,
                    body: advisory.clone(),
                };
            }
            if request.url.contains("/data/v1/epss") {
                return HttpResponse {
                    status: 200,
                    body: r#"{"data":[{"cve":"CVE-2021-23337","epss":"0.21333","percentile":"0.95","date":"2026-10-24"}]}"#.to_string(),
                };
            }
            if request.url.contains("known_exploited") {
                return HttpResponse {
                    status: 200,
                    body: r#"{"catalogVersion":"2026.10.24","vulnerabilities":[{"cveID":"CVE-2021-23337","dateAdded":"2026-01-01","dueDate":"2026-02-01","knownRansomwareCampaignUse":"Unknown","vulnerabilityName":"lodash","requiredAction":"apply updates"}]}"#.to_string(),
                };
            }
            HttpResponse {
                status: 500,
                body: format!("unexpected {}", request.url),
            }
        });
        let hour = Duration::from_secs(3_600);
        let mut online = lodash_options(dir.path(), 1_700_000_000);
        online.enrich = true;
        online.ttl_epss = hour;
        online.ttl_kev = hour;
        let first = scan_with(&http, "https://api.osv.dev", dir.path(), &online)
            .await
            .expect("online");
        let score = first.findings[0].score;
        assert!(first.findings[0].signals.kev.is_some());

        let mut offline = online.clone();
        offline.offline = true;
        offline.now = Some(1_700_000_000 + 7_200);
        let second = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &offline,
        )
        .await
        .expect("stale offline");
        assert_eq!(second.findings[0].score, score);
        assert_eq!(second.findings[0].tier, first.findings[0].tier);
        assert!(second.findings[0].signals.kev.is_some());
        let warnings = second.warnings.join("\n");
        assert!(warnings.contains("using the stale catalog"), "{warnings}");
        assert!(warnings.contains("2h old"), "{warnings}");
        assert!(warnings.contains("using the stale score"), "{warnings}");
        assert!(!warnings.contains("not in the cache"), "{warnings}");

        offline.strict_cache = true;
        let err = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &offline,
        )
        .await
        .expect_err("strict");
        let message = err.to_string();
        assert!(message.contains("offline cache is stale"), "{message}");
        assert!(message.contains("KEV"), "{message}");
        assert!(message.contains("EPSS"), "{message}");
        assert!(message.contains("2h old"), "{message}");
    }

    #[tokio::test]
    async fn no_dev_lockfile_count_is_filtered() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("composer.lock"),
            r#"{
                "packages": [{"name": "acme/prod", "version": "1.0.0"}],
                "packages-dev": [{"name": "acme/devtool", "version": "2.0.0"}]
            }"#,
        )
        .expect("lock");
        let http = FakeHttp::with_handler(|request: &RecordedRequest| {
            let body: Value = serde_json::from_str(&request.body).unwrap_or(json!({}));
            let queries = body["queries"]
                .as_array()
                .map(|items| items.len())
                .unwrap_or(0);
            assert_eq!(queries, 1, "{}", request.body);
            assert!(!request.body.contains("acme/devtool"), "{}", request.body);
            HttpResponse {
                status: 200,
                body: json!({"results": [{}]}).to_string(),
            }
        });
        let options = ScanOptions {
            no_dev: true,
            ..ScanOptions::default()
        };
        let report = scan_with(&http, "https://api.osv.dev", dir.path(), &options)
            .await
            .expect("scan");
        assert_eq!(report.context.lockfiles[0].packages, 1);
        assert_eq!(report.summary.packages_scanned, 1);
    }

    #[tokio::test]
    async fn bun_lock_without_a_supported_file_names_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("bun.lock"), "").expect("bun");
        let err = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            dir.path(),
            &ScanOptions::default(),
        )
        .await
        .expect_err("bun only");
        let message = err.to_string();
        assert!(message.contains("no supported lockfile"), "{message}");
        assert!(message.contains("bun.lock"), "{message}");
    }

    #[tokio::test]
    async fn bun_lock_beside_a_lockfile_is_a_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
        )
        .expect("lock");
        fs::write(dir.path().join("bun.lock"), "").expect("bun");
        let report = scan_with(
            &fake_osv(),
            "https://api.osv.dev",
            dir.path(),
            &ScanOptions::default(),
        )
        .await
        .expect("scan");
        assert_eq!(report.findings.len(), 1);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("bun.lock")),
            "{:?}",
            report.warnings
        );
    }

    #[test]
    fn minimum_covering_fix_picks_the_highest_floor() {
        let recommended = minimum_covering_fix(&[
            vec!["4.17.21".to_string(), "4.18.0".to_string()],
            vec!["4.17.20".to_string()],
        ]);
        assert_eq!(recommended.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn minimum_covering_fix_uses_the_other_advisory_when_it_is_higher() {
        let recommended = minimum_covering_fix(&[
            vec!["v1.2.3".to_string()],
            vec!["1.4.0".to_string(), "1.9.0".to_string()],
        ]);
        assert_eq!(recommended.as_deref(), Some("1.4.0"));
    }

    #[test]
    fn minimum_covering_fix_is_none_without_a_parseable_fix() {
        assert_eq!(minimum_covering_fix(&[]), None);
        assert_eq!(
            minimum_covering_fix(&[vec!["1.0.0".to_string()], vec![]]),
            None
        );
        assert_eq!(
            minimum_covering_fix(&[vec!["not-semver".to_string()]]),
            None
        );
    }

    const GO_MODIFIED: &str = "2026-10-28T00:00:00Z";

    fn fixture(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(rel)
    }

    fn go_bodies() -> (String, String) {
        (
            fs::read_to_string(fixture("osv/go/GO-2026-5932.json")).expect("openpgp advisory"),
            fs::read_to_string(fixture("osv/go/GO-2099-0001.json")).expect("plain advisory"),
        )
    }

    fn go_http() -> FakeHttp {
        let (openpgp, plain) = go_bodies();
        FakeHttp::with_handler(move |request: &RecordedRequest| {
            if request.method == "POST" && request.url.ends_with("/v1/querybatch") {
                let body: Value = serde_json::from_str(&request.body).expect("query json");
                let queries = body["queries"].as_array().expect("queries");
                let results: Vec<Value> = queries
                    .iter()
                    .map(|query| {
                        if query["package"]["name"] == "golang.org/x/crypto" {
                            json!({"vulns": [
                                {"id": "GO-2026-5932", "modified": GO_MODIFIED},
                                {"id": "GO-2099-0001", "modified": GO_MODIFIED}
                            ]})
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
            if request.method == "GET" && request.url.ends_with("/v1/vulns/GO-2026-5932") {
                return HttpResponse {
                    status: 200,
                    body: openpgp.clone(),
                };
            }
            if request.method == "GET" && request.url.ends_with("/v1/vulns/GO-2099-0001") {
                return HttpResponse {
                    status: 200,
                    body: plain.clone(),
                };
            }
            HttpResponse {
                status: 404,
                body: format!("unexpected {}", request.url),
            }
        })
    }

    fn go_scan_options() -> ScanOptions {
        ScanOptions {
            enrich: true,
            ..ScanOptions::default()
        }
    }

    fn finding_by_id<'a>(report: &'a Report, id: &str) -> &'a Finding {
        report
            .findings
            .iter()
            .find(|finding| finding.advisory.id == id)
            .unwrap_or_else(|| panic!("missing {id}"))
    }

    #[tokio::test]
    async fn argon2_only_keeps_the_openpgp_finding_and_the_score() {
        let report = scan_with(
            &go_http(),
            "https://api.osv.dev",
            &fixture("go/argon2-only"),
            &go_scan_options(),
        )
        .await
        .expect("scan");
        assert_eq!(report.findings.len(), 2);
        let openpgp = finding_by_id(&report, "GO-2026-5932");
        let plain = finding_by_id(&report, "GO-2099-0001");
        assert_eq!(
            openpgp.import_note.as_deref(),
            Some(crate::go_imports::IMPORT_NOT_SEEN)
        );
        assert!(plain.import_note.is_none());
        assert!(plain.advisory.imports.is_empty());
        assert_eq!(openpgp.score, plain.score);
        assert_eq!(openpgp.score, 20);
        assert_eq!(openpgp.tier, plain.tier);
        let openpgp_import = openpgp
            .advisory
            .imports
            .iter()
            .find(|item| item.path == "golang.org/x/crypto/openpgp")
            .expect("openpgp path");
        assert_eq!(openpgp_import.symbols, vec!["ReadMessage".to_string()]);
        assert!(openpgp
            .advisory
            .imports
            .iter()
            .all(|item| item.path != "golang.org/x/crypto/argon2"));

        let json = crate::report::render_json(&report).expect("json");
        let parsed: Value = serde_json::from_str(&json).expect("json value");
        let schema: Value = serde_json::from_str(
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/report.v1.json"),
            )
            .expect("schema text"),
        )
        .expect("schema");
        let validator = jsonschema::validator_for(&schema).expect("schema compiles");
        assert!(validator.validate(&parsed).is_ok(), "{json}");
        let rows = parsed["findings"].as_array().expect("findings");
        let noted = rows
            .iter()
            .find(|row| row["id"] == "GO-2026-5932")
            .expect("row");
        assert_eq!(noted["import_note"], "imported package not seen");
        assert_eq!(noted["score"], 20);
        let unnoted = rows
            .iter()
            .find(|row| row["id"] == "GO-2099-0001")
            .expect("row");
        assert!(unnoted.get("import_note").is_none());

        let markdown = crate::report::render_markdown(&report, 20);
        assert!(markdown.contains("GO-2026-5932 (imported package not seen)"));
        assert!(markdown.contains("imported package not seen\n"));
        let sarif = crate::report::render_sarif(&report).expect("sarif");
        assert!(sarif.contains("imported package not seen"));
        let gitlab = crate::report::render_gitlab(&report).expect("gitlab");
        assert!(gitlab.contains("imported package not seen"));
    }

    #[tokio::test]
    async fn an_aliased_openpgp_import_leaves_the_note_off() {
        let report = scan_with(
            &go_http(),
            "https://api.osv.dev",
            &fixture("go/openpgp-alias"),
            &go_scan_options(),
        )
        .await
        .expect("scan");
        let openpgp = finding_by_id(&report, "GO-2026-5932");
        let plain = finding_by_id(&report, "GO-2099-0001");
        assert!(openpgp.import_note.is_none());
        assert!(plain.import_note.is_none());
        assert_eq!(openpgp.score, 20);
        assert_eq!(plain.score, 20);
        let json = crate::report::render_json(&report).expect("json");
        assert!(!json.contains("import_note"));
        let markdown = crate::report::render_markdown(&report, 20);
        assert!(!markdown.contains("imported package not seen"));
    }

    #[tokio::test]
    async fn offline_cache_still_attaches_the_import_note() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("cache.db");
        let now = 1_700_000_000;
        {
            let cache = Cache::open(&cache_path).expect("cache");
            let (openpgp, plain) = go_bodies();
            cache
                .put_osv("GO-2026-5932", GO_MODIFIED, &openpgp, now)
                .expect("put");
            cache
                .put_osv("GO-2099-0001", GO_MODIFIED, &plain, now)
                .expect("put");
            cache
                .put_osv_query(
                    "Go",
                    "golang.org/x/crypto",
                    "v0.31.0",
                    &[
                        crate::cache::CachedOsvRef {
                            id: "GO-2026-5932".to_string(),
                            modified: GO_MODIFIED.to_string(),
                        },
                        crate::cache::CachedOsvRef {
                            id: "GO-2099-0001".to_string(),
                            modified: GO_MODIFIED.to_string(),
                        },
                    ],
                    now,
                )
                .expect("query");
            assert_eq!(
                cache.schema_version().expect("schema"),
                crate::cache::SCHEMA_VERSION
            );
        }
        let options = ScanOptions {
            enrich: true,
            offline: true,
            no_cache: false,
            cache_db: Some(cache_path),
            now: Some(now),
            ..ScanOptions::default()
        };
        let report = scan_with(
            &FakeHttp::forbid(),
            "https://api.osv.dev",
            &fixture("go/argon2-only"),
            &options,
        )
        .await
        .expect("offline scan");
        assert!(
            report
                .warnings
                .iter()
                .all(|warning| !warning.contains("offline:")),
            "{:?}",
            report.warnings
        );
        let openpgp = finding_by_id(&report, "GO-2026-5932");
        assert_eq!(
            openpgp.import_note.as_deref(),
            Some("imported package not seen")
        );
        assert_eq!(openpgp.score, 20);
        assert!(finding_by_id(&report, "GO-2099-0001").import_note.is_none());
    }
}
