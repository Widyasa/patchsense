//! Scan orchestration: find lockfiles, parse them, and load OSV advisories.
//!
//! This pass does not score. The binary prints the raw list. Exit code 1 and
//! `--fail-on` arrive with the score engine.

use std::path::Path;

use crate::discovery::discover;
use crate::error::CoreError;
use crate::http::HttpClient;
use crate::lockfile::parser_for;
use crate::model::{Finding, Report, Tier};
use crate::osv::{fetch_advisories, query_batch};

/// Discover lockfiles under `root`, parse them, and attach OSV advisories.
///
/// `root` may be a directory or one file. No recognised lockfile is
/// [`CoreError::NoLockfile`]. A file that fails to parse, when nothing else
/// parsed, is returned as that parse error. Warnings from a successful parse
/// are kept on the report.
pub async fn scan_path<C>(client: &C, base_url: &str, root: &Path) -> Result<Report, CoreError>
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
        let content = std::fs::read_to_string(file).map_err(|source| CoreError::Io {
            path: file.clone(),
            source,
        })?;
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
                    packages.push(package);
                }
            }
            Err(err) => failures.push(err),
        }
    }

    if failures.len() == files.len() {
        return Err(failures.swap_remove(0));
    }
    for err in failures {
        warnings.push(err.to_string());
    }

    packages.sort_by(|left, right| {
        (&left.source_file, &left.name, &left.version).cmp(&(
            &right.source_file,
            &right.name,
            &right.version,
        ))
    });

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
}
