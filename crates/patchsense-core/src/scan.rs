//! Scan orchestration: find lockfiles, parse them, and load OSV advisories.
//!
//! This pass does not score. The binary prints the raw list. Exit code 1 and
//! `--fail-on` arrive with the score engine.
//!
//! `--keep-going` (the default) turns a bad lockfile into a warning unless
//! every lockfile failed. Packages are deduped on ecosystem, name, and version
//! before the OSV query. `--ecosystem` and `--no-dev` drop packages first.

use std::collections::BTreeMap;
use std::path::Path;

use crate::discovery::discover;
use crate::error::CoreError;
use crate::http::HttpClient;
use crate::lockfile::parser_for;
use crate::model::{Ecosystem, Finding, Package, Report, Tier};
use crate::osv::{fetch_advisories, query_batch};

/// Filters applied after parsing and before the OSV query.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// When false, the first lockfile that cannot be read or parsed fails the scan.
    pub keep_going: bool,
    /// Ecosystems to keep. `None` keeps every ecosystem.
    pub ecosystems: Option<Vec<Ecosystem>>,
    /// Drop packages the parser marked `dev`.
    pub no_dev: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            keep_going: true,
            ecosystems: None,
            no_dev: false,
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
    let files = discover(root, &[])?;
    if files.is_empty() {
        return Err(CoreError::NoLockfile {
            path: root.to_path_buf(),
        });
    }

    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    let mut failures = Vec::new();

    for file in &files {
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
                warnings.extend(parsed.warnings);
                let source = source_label(root, file);
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

    let matched = query_batch(client, base_url, &packages).await?;
    let mut findings = Vec::new();
    for (package, vulns) in packages.iter().zip(matched) {
        if vulns.is_empty() {
            continue;
        }
        let ids: Vec<String> = vulns.into_iter().map(|vuln| vuln.id).collect();
        let advisories = fetch_advisories(client, base_url, &ids, package).await?;
        for advisory in advisories {
            findings.push(Finding {
                advisory,
                package: package.clone(),
                tier: Tier::Defer,
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

    Ok(Report {
        schema_version: 1,
        findings,
        warnings,
    })
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
}
