//! OSV query client.
//!
//! `querybatch` is chunked at [`OSV_BATCH_SIZE`]. A result with
//! `next_page_token` is queried again by itself until the token is gone.
//! The returned vectors line up with the input packages.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::cache::{self, Cache, CachedOsvRef};
use crate::error::CoreError;
use crate::http::{join_url, HttpClient, HttpResponse};
use crate::model::{Advisory, GoImport, Package, Severity};

/// Maximum number of packages in one `POST /v1/querybatch` body.
pub const OSV_BATCH_SIZE: usize = 1000;

/// An advisory id returned by querybatch, before the full advisory is fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvVulnRef {
    /// OSV id, for example a GHSA.
    pub id: String,
    /// OSV `modified` timestamp. Empty when the response omitted it.
    pub modified: String,
}

/// Query OSV for every package. One inner vector per package, same order.
pub async fn query_batch<C: HttpClient>(
    client: &C,
    base_url: &str,
    packages: &[Package],
) -> Result<Vec<Vec<OsvVulnRef>>, CoreError> {
    query_batch_sized(client, base_url, packages, OSV_BATCH_SIZE).await
}

/// Same as [`query_batch`] with an explicit chunk size. Tests pass 1000; callers
/// should use [`query_batch`].
pub async fn query_batch_sized<C: HttpClient>(
    client: &C,
    base_url: &str,
    packages: &[Package],
    batch_size: usize,
) -> Result<Vec<Vec<OsvVulnRef>>, CoreError> {
    if batch_size == 0 {
        return Err(CoreError::Osv {
            url: join_url(base_url, "/v1/querybatch"),
            message: "batch size must be at least 1".to_string(),
        });
    }
    let mut combined = Vec::with_capacity(packages.len());
    for chunk in packages.chunks(batch_size) {
        combined.extend(query_chunk(client, base_url, chunk).await?);
    }
    Ok(combined)
}

async fn query_chunk<C: HttpClient>(
    client: &C,
    base_url: &str,
    packages: &[Package],
) -> Result<Vec<Vec<OsvVulnRef>>, CoreError> {
    let url = join_url(base_url, "/v1/querybatch");
    let mut found = vec![Vec::new(); packages.len()];
    let mut pending: Vec<usize> = (0..packages.len()).collect();
    let mut tokens = vec![None; packages.len()];
    let mut pages = 0u32;

    while !pending.is_empty() {
        pages += 1;
        if pages > 20 {
            return Err(CoreError::Osv {
                url: url.clone(),
                message: "stopped after 20 querybatch pages".to_string(),
            });
        }
        let queries = Value::Array(
            pending
                .iter()
                .map(|index| query_body(&packages[*index], tokens[*index].as_deref()))
                .collect(),
        );
        let response = client
            .post_json(&url, &json!({ "queries": queries }))
            .await?;
        let parsed = parse_querybatch(&url, &response, pending.len())?;
        let mut next_pending = Vec::new();
        for (offset, result) in parsed.into_iter().enumerate() {
            let index = pending[offset];
            if let Some(token) = result.next_page_token.clone() {
                if !token.is_empty() {
                    tokens[index] = Some(token);
                    next_pending.push(index);
                }
            }
            found[index].extend(result.vulns);
        }
        pending = next_pending;
    }
    Ok(found)
}

fn query_body(package: &Package, page_token: Option<&str>) -> Value {
    let mut query = json!({
        "package": {
            "ecosystem": package.ecosystem.as_osv_str(),
            "name": package.name,
        },
        "version": package.version,
    });
    if let Some(token) = page_token {
        query["page_token"] = Value::String(token.to_string());
    }
    query
}

#[derive(Debug, Deserialize)]
struct QueryBatchBody {
    results: Vec<QueryBatchItem>,
}

#[derive(Debug, Deserialize)]
struct QueryBatchItem {
    #[serde(default)]
    vulns: Vec<OsvVulnRef>,
    #[serde(default)]
    next_page_token: Option<String>,
}

fn parse_querybatch(
    url: &str,
    response: &HttpResponse,
    expected: usize,
) -> Result<Vec<QueryBatchItem>, CoreError> {
    if !(200..300).contains(&response.status) {
        return Err(CoreError::Http {
            url: url.to_string(),
            message: format!("status {}", response.status),
        });
    }
    let body: QueryBatchBody =
        serde_json::from_str(&response.body).map_err(|err| CoreError::Osv {
            url: url.to_string(),
            message: err.to_string(),
        })?;
    if body.results.len() != expected {
        return Err(CoreError::Osv {
            url: url.to_string(),
            message: format!("expected {expected} results, got {}", body.results.len()),
        });
    }
    Ok(body.results)
}

/// How many vuln documents are fetched at once.
pub const OSV_VULN_CONCURRENCY: usize = 8;

/// Fetch advisory documents in parallel and keep `ids` order.
pub async fn fetch_advisories<C>(
    client: &C,
    base_url: &str,
    ids: &[String],
    package: &Package,
) -> Result<Vec<Advisory>, CoreError>
where
    C: HttpClient + Clone + 'static,
{
    let limit = OSV_VULN_CONCURRENCY.max(1);
    let semaphore = Arc::new(Semaphore::new(limit));
    let mut handles = Vec::with_capacity(ids.len());
    for id in ids {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|err| CoreError::Osv {
                url: join_url(base_url, "/v1/vulns"),
                message: format!("failed to acquire fetch permit: {err}"),
            })?;
        let client = client.clone();
        let id = id.clone();
        let package = package.clone();
        let base_url = base_url.to_string();
        handles.push(tokio::spawn(async move {
            let result = fetch_advisory(&client, &base_url, &id, &package).await;
            drop(permit);
            result
        }));
    }
    let mut advisories = Vec::with_capacity(handles.len());
    for handle in handles {
        let advisory = handle.await.map_err(|err| CoreError::Osv {
            url: join_url(base_url, "/v1/vulns"),
            message: format!("advisory fetch task failed: {err}"),
        })??;
        advisories.push(advisory);
    }
    Ok(advisories)
}

/// How a scan should use the SQLite cache while loading advisory documents.
pub struct AdvisoryCache<'a> {
    /// Open cache. `None` always uses the network (unless `offline`).
    pub cache: Option<&'a Cache>,
    /// Skip the network. A miss is an error.
    pub offline: bool,
    /// Unix seconds for the TTL check and for new rows.
    pub now: i64,
    /// Maximum age of a cached row.
    pub ttl: std::time::Duration,
}

/// Where a cached or downloaded OSV row came from.
#[derive(Debug, Default, Clone)]
pub(crate) struct FetchOrigin {
    network: bool,
    cached_at: Vec<i64>,
}

impl FetchOrigin {
    pub(crate) fn note_cache(&mut self, at: i64) {
        self.cached_at.push(at);
    }

    pub(crate) fn note_network(&mut self) {
        self.network = true;
    }

    pub(crate) fn merge(&mut self, other: &FetchOrigin) {
        self.network |= other.network;
        self.cached_at.extend(other.cached_at.iter().copied());
    }

    /// True when every row used was a cache hit and at least one row was used.
    pub(crate) fn served_from_cache(&self) -> bool {
        !self.network && !self.cached_at.is_empty()
    }

    /// Oldest cache timestamp, or `now` when this run downloaded data.
    pub(crate) fn fetched_at(&self, now: i64) -> i64 {
        if self.network || self.cached_at.is_empty() {
            now
        } else {
            self.cached_at.iter().copied().min().unwrap_or(now)
        }
    }
}

/// Fetch advisories, using `cache` when `modified` matches and the TTL holds.
///
/// An offline miss is an error. It does not call `client`.
pub(crate) async fn fetch_advisories_cached<C>(
    client: &C,
    base_url: &str,
    vulns: &[OsvVulnRef],
    package: &Package,
    fetch: &AdvisoryCache<'_>,
) -> Result<(Vec<Advisory>, FetchOrigin), CoreError>
where
    C: HttpClient,
{
    let mut advisories = Vec::new();
    let mut origin = FetchOrigin::default();
    for vuln in vulns {
        match fetch_one_cached(client, base_url, vuln, package, fetch).await? {
            CachedFetch::Hit {
                advisory,
                cached_at: Some(at),
            } => {
                origin.note_cache(at);
                advisories.push(advisory);
            }
            CachedFetch::Hit {
                advisory,
                cached_at: None,
            } => {
                origin.note_network();
                advisories.push(advisory);
            }
        }
    }
    Ok((advisories, origin))
}

enum CachedFetch {
    Hit {
        advisory: Advisory,
        cached_at: Option<i64>,
    },
}

async fn fetch_one_cached<C: HttpClient>(
    client: &C,
    base_url: &str,
    vuln: &OsvVulnRef,
    package: &Package,
    fetch: &AdvisoryCache<'_>,
) -> Result<CachedFetch, CoreError> {
    let url = join_url(base_url, &format!("/v1/vulns/{}", vuln.id));
    if let Some(cache) = fetch.cache {
        if let Some((json, fetched_at)) =
            cache.get_osv_document(&vuln.id, &vuln.modified, fetch.now, fetch.ttl)?
        {
            return Ok(CachedFetch::Hit {
                advisory: advisory_from_json(&url, &json, package)?,
                cached_at: Some(fetched_at),
            });
        }
    }
    if fetch.offline {
        if let Some(cache) = fetch.cache {
            if let Some(fetched_at) = cache.osv_document_fetched_at(&vuln.id)? {
                if !cache::fresh(fetched_at, fetch.now, fetch.ttl) {
                    return Err(CoreError::OfflineCache {
                        message: format!(
                            "offline cache expired: advisory {} for {}@{} is {} old, past the {} TTL. Run a scan without --offline to refresh the cache",
                            vuln.id,
                            package.name,
                            package.version,
                            cache::format_span(cache::row_age(fetched_at, fetch.now)),
                            cache::format_ttl(fetch.ttl)
                        ),
                    });
                }
            }
        }
        return Err(CoreError::OfflineCache {
            message: format!(
                "offline cache is missing advisory {} for {}@{}. Run a scan without --offline to fill the cache",
                vuln.id, package.name, package.version
            ),
        });
    }
    let response = client.get(&url).await?;
    if !(200..300).contains(&response.status) {
        return Err(CoreError::Http {
            url,
            message: format!("status {}", response.status),
        });
    }
    if let Some(cache) = fetch.cache {
        cache.put_osv(&vuln.id, &vuln.modified, &response.body, fetch.now)?;
    }
    Ok(CachedFetch::Hit {
        advisory: advisory_from_json(&url, &response.body, package)?,
        cached_at: None,
    })
}

/// Remember a `querybatch` result. `modified` is stored with each id.
pub fn cache_query(
    cache: &Cache,
    package: &Package,
    vulns: &[OsvVulnRef],
    now: i64,
) -> Result<(), CoreError> {
    let refs = vulns
        .iter()
        .map(|vuln| CachedOsvRef {
            id: vuln.id.clone(),
            modified: vuln.modified.clone(),
        })
        .collect::<Vec<_>>();
    cache.put_osv_query(
        package.ecosystem.as_osv_str(),
        &package.name,
        &package.version,
        &refs,
        now,
    )
}

/// A cached `querybatch` result and the Unix time it was stored.
pub struct CachedQuery {
    /// Advisory ids returned for the package.
    pub vulns: Vec<OsvVulnRef>,
    /// Unix seconds stored with the row.
    pub fetched_at: i64,
}

/// Load a cached `querybatch` result. `None` means a miss or an expired row.
pub fn cached_query(
    cache: &Cache,
    package: &Package,
    now: i64,
    ttl: std::time::Duration,
) -> Result<Option<CachedQuery>, CoreError> {
    let Some((refs, fetched_at)) = cache.get_osv_query(
        package.ecosystem.as_osv_str(),
        &package.name,
        &package.version,
        now,
        ttl,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(CachedQuery {
        vulns: refs
            .into_iter()
            .map(|reference| OsvVulnRef {
                id: reference.id,
                modified: reference.modified,
            })
            .collect(),
        fetched_at,
    }))
}

/// GET one advisory and compute fixed versions for `package`.
pub async fn fetch_advisory<C: HttpClient>(
    client: &C,
    base_url: &str,
    id: &str,
    package: &Package,
) -> Result<Advisory, CoreError> {
    let url = join_url(base_url, &format!("/v1/vulns/{id}"));
    let response = client.get(&url).await?;
    if !(200..300).contains(&response.status) {
        return Err(CoreError::Http {
            url,
            message: format!("status {}", response.status),
        });
    }
    advisory_from_json(&url, &response.body, package)
}

/// Parse an OSV vulnerability document into an [`Advisory`].
pub fn advisory_from_json(url: &str, body: &str, package: &Package) -> Result<Advisory, CoreError> {
    let doc: Value = serde_json::from_str(body).map_err(|err| CoreError::Osv {
        url: url.to_string(),
        message: err.to_string(),
    })?;
    let id = doc["id"].as_str().unwrap_or("").to_string();
    if id.is_empty() {
        return Err(CoreError::Osv {
            url: url.to_string(),
            message: "advisory is missing id".to_string(),
        });
    }
    let mut aliases = doc["aliases"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    aliases.sort();
    let summary = doc["summary"].as_str().unwrap_or("").to_string();
    let severity = doc["severity"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let kind = item["type"].as_str()?.to_string();
                    let score = item["score"].as_str()?.to_string();
                    Some(Severity { kind, score })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let database_specific_severity = doc["database_specific"]["severity"]
        .as_str()
        .map(str::to_string);
    let mut references = doc["references"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["url"].as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    references.sort();
    let mut fixed_versions = fixed_versions_for(&doc, package);
    fixed_versions.sort();
    fixed_versions.dedup();
    Ok(Advisory {
        id,
        aliases,
        summary,
        severity,
        database_specific_severity,
        references,
        fixed_versions,
        imports: imports_for(&doc, package),
    })
}

/// Import paths from affected entries that match `package`.
///
/// Only the Go ecosystem is read. Paths are deduped and symbols for the same
/// path are merged. Other ecosystems, and Go entries with no `imports` list,
/// contribute nothing.
fn imports_for(doc: &Value, package: &Package) -> Vec<GoImport> {
    if package.ecosystem != crate::model::Ecosystem::Go {
        return Vec::new();
    }
    let Some(affected) = doc["affected"].as_array() else {
        return Vec::new();
    };
    let mut by_path: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for entry in affected {
        if !affected_matches(entry, package) {
            continue;
        }
        let Some(imports) = entry["ecosystem_specific"]["imports"].as_array() else {
            continue;
        };
        for item in imports {
            let Some(path) = item["path"]
                .as_str()
                .map(str::trim)
                .filter(|path| !path.is_empty())
            else {
                continue;
            };
            let symbols = by_path.entry(path.to_string()).or_default();
            let Some(listed) = item["symbols"].as_array() else {
                continue;
            };
            for symbol in listed {
                if let Some(name) = symbol
                    .as_str()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                {
                    symbols.insert(name.to_string());
                }
            }
        }
    }
    by_path
        .into_iter()
        .map(|(path, symbols)| GoImport {
            path,
            symbols: symbols.into_iter().collect(),
        })
        .collect()
}

fn fixed_versions_for(doc: &Value, package: &Package) -> Vec<String> {
    let Some(affected) = doc["affected"].as_array() else {
        return Vec::new();
    };
    let mut fixed = Vec::new();
    for entry in affected {
        if !affected_matches(entry, package) {
            continue;
        }
        let Some(ranges) = entry["ranges"].as_array() else {
            continue;
        };
        for range in ranges {
            let Some(events) = range["events"].as_array() else {
                continue;
            };
            if let Some(version) = fixed_in_events(events, &package.version) {
                fixed.push(version);
            }
        }
    }
    fixed
}

fn affected_matches(entry: &Value, package: &Package) -> bool {
    let name = entry["package"]["name"].as_str().unwrap_or("");
    let ecosystem = entry["package"]["ecosystem"].as_str().unwrap_or("");
    name == package.name && ecosystem.eq_ignore_ascii_case(package.ecosystem.as_osv_str())
}

fn fixed_in_events(events: &[Value], installed: &str) -> Option<String> {
    let mut introduced: Option<String> = None;
    for event in events {
        if let Some(start) = event["introduced"].as_str() {
            introduced = Some(start.to_string());
        } else if let Some(fixed) = event["fixed"].as_str() {
            if let Some(start) = introduced.as_deref() {
                if version_in_half_open(installed, start, fixed) {
                    return Some(fixed.to_string());
                }
            }
            introduced = None;
        } else if event["last_affected"].is_string() {
            introduced = None;
        }
    }
    None
}

fn version_in_half_open(installed: &str, start: &str, end: &str) -> bool {
    match (
        parse_osv_version(installed),
        parse_osv_version(start),
        parse_osv_version(end),
    ) {
        (Some(installed), Some(start), Some(end)) => installed >= start && installed < end,
        _ => false,
    }
}

fn parse_osv_version(value: &str) -> Option<semver::Version> {
    let trimmed = value.trim().trim_start_matches('v');
    if trimmed.is_empty() || trimmed == "0" || trimmed == "*" {
        return Some(semver::Version::new(0, 0, 0));
    }
    semver::Version::parse(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{FakeHttp, HttpResponse, RecordedRequest};
    use crate::model::Ecosystem;
    use std::fs;
    use std::path::PathBuf;

    fn package(name: &str) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            version: "1.0.0".to_string(),
            direct: Some(true),
            dev: false,
            source_file: "package-lock.json".to_string(),
            source_files: Vec::new(),
            line: None,
        }
    }

    #[tokio::test]
    async fn chunks_2500_packages_into_three_requests() {
        let sizes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sizes_for_handler = std::sync::Arc::clone(&sizes);
        let fake = FakeHttp::with_handler(move |request: &RecordedRequest| {
            let body: Value = serde_json::from_str(&request.body).expect("json");
            let queries = body["queries"].as_array().expect("queries");
            sizes_for_handler.lock().expect("sizes").push(queries.len());
            let results = vec![json!({}); queries.len()];
            HttpResponse {
                status: 200,
                body: json!({ "results": results }).to_string(),
            }
        });
        let packages: Vec<Package> = (0..2500)
            .map(|index| package(&format!("pkg-{index}")))
            .collect();
        let found = query_batch(&fake, "https://api.osv.dev", &packages)
            .await
            .expect("query");
        assert_eq!(found.len(), 2500);
        assert!(found.iter().all(|vulns| vulns.is_empty()));
        let sizes = sizes.lock().expect("sizes").clone();
        assert_eq!(sizes, vec![1000, 1000, 500]);
    }

    #[tokio::test]
    async fn follows_next_page_token_and_keeps_order() {
        let fake = FakeHttp::with_handler(|request: &RecordedRequest| {
            let body: Value = serde_json::from_str(&request.body).expect("json");
            let queries = body["queries"].as_array().expect("queries");
            let mut results = Vec::new();
            for query in queries {
                let name = query["package"]["name"].as_str().unwrap_or("");
                let token = query.get("page_token").and_then(Value::as_str);
                if name == "paged" && token.is_none() {
                    results.push(json!({
                        "vulns": [{"id": "PAGE-1", "modified": "2024-01-01T00:00:00Z"}],
                        "next_page_token": "page-2"
                    }));
                } else if name == "paged" && token == Some("page-2") {
                    results.push(json!({
                        "vulns": [{"id": "PAGE-2", "modified": "2024-02-01T00:00:00Z"}]
                    }));
                } else {
                    results.push(json!({
                        "vulns": [{"id": format!("ID-{name}"), "modified": "2024-01-01T00:00:00Z"}]
                    }));
                }
            }
            HttpResponse {
                status: 200,
                body: json!({ "results": results }).to_string(),
            }
        });
        let packages = vec![package("alpha"), package("paged"), package("omega")];
        let found = query_batch(&fake, "https://api.osv.dev", &packages)
            .await
            .expect("query");
        assert_eq!(found[0][0].id, "ID-alpha");
        assert_eq!(
            found[1]
                .iter()
                .map(|vuln| vuln.id.as_str())
                .collect::<Vec<_>>(),
            vec!["PAGE-1", "PAGE-2"]
        );
        assert_eq!(found[2][0].id, "ID-omega");
        let posts = fake.recorded();
        assert_eq!(posts.len(), 2);
        let second: Value = serde_json::from_str(&posts[1].body).expect("second body");
        let second_queries = second["queries"].as_array().expect("queries");
        assert_eq!(second_queries.len(), 1);
        assert_eq!(second_queries[0]["page_token"], "page-2");
        assert_eq!(second_queries[0]["package"]["name"], "paged");
    }

    #[tokio::test]
    async fn real_querybatch_fixture_keeps_lodash_ids_in_order() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/osv/querybatch_lodash.json");
        let body = fs::read_to_string(&path).expect("fixture");
        let fake = FakeHttp::script(vec![HttpResponse { status: 200, body }]);
        let packages = vec![
            Package {
                name: "lodash".to_string(),
                version: "4.17.15".to_string(),
                ..package("lodash")
            },
            Package {
                name: "left-pad".to_string(),
                version: "1.3.0".to_string(),
                ..package("left-pad")
            },
        ];
        let found = query_batch(&fake, "https://api.osv.dev", &packages)
            .await
            .expect("fixture query");
        assert!(found[0].iter().any(|vuln| vuln.id == "GHSA-35jh-r3h4-6jhm"));
        assert!(found[1].is_empty());
        assert_eq!(fake.recorded().len(), 1);
    }

    fn lodash_package(version: &str) -> Package {
        Package {
            version: version.to_string(),
            ..package("lodash")
        }
    }

    #[tokio::test]
    async fn lodash_advisory_fixture_has_cve_vector_and_fix() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/osv/vulns/GHSA-35jh-r3h4-6jhm.json");
        let body = fs::read_to_string(&path).expect("fixture");
        let fake = FakeHttp::with_handler(move |request: &RecordedRequest| {
            assert!(request.url.ends_with("/v1/vulns/GHSA-35jh-r3h4-6jhm"));
            HttpResponse {
                status: 200,
                body: body.clone(),
            }
        });
        let vulnerable = lodash_package("4.17.15");
        let advisories = fetch_advisories(
            &fake,
            "https://api.osv.dev",
            &["GHSA-35jh-r3h4-6jhm".to_string()],
            &vulnerable,
        )
        .await
        .expect("fetch");
        assert_eq!(advisories.len(), 1);
        let advisory = &advisories[0];
        assert_eq!(advisory.aliases, vec!["CVE-2021-23337".to_string()]);
        assert!(advisory.severity.iter().any(|item| item.kind == "CVSS_V3"
            && item.score == "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"));
        assert_eq!(advisory.fixed_versions, vec!["4.17.21".to_string()]);
        assert_eq!(advisory.database_specific_severity.as_deref(), Some("HIGH"));
        assert!(advisory.imports.is_empty());
        insta::assert_yaml_snapshot!("lodash_advisory", advisory);

        let go_body = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/osv/go/GO-2026-5932.json"),
        )
        .expect("go fixture");
        let go_package = Package {
            ecosystem: Ecosystem::Go,
            name: "golang.org/x/crypto".to_string(),
            version: "v0.31.0".to_string(),
            ..package("golang.org/x/crypto")
        };
        let go_advisory = advisory_from_json("fixture", &go_body, &go_package).expect("go");
        assert_eq!(
            go_advisory
                .imports
                .iter()
                .map(|item| item.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "golang.org/x/crypto/openpgp",
                "golang.org/x/crypto/openpgp/armor",
                "golang.org/x/crypto/openpgp/packet",
            ]
        );
        assert_eq!(
            go_advisory.imports[0].symbols,
            vec!["ReadMessage".to_string()]
        );
        let plain = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/osv/go/GO-2099-0001.json"),
        )
        .expect("plain fixture");
        let plain_advisory = advisory_from_json("fixture", &plain, &go_package).expect("plain");
        assert!(plain_advisory.imports.is_empty());

        let fixed = lodash_package("4.17.21");
        let parsed = advisory_from_json("fixture", &fs::read_to_string(&path).unwrap(), &fixed)
            .expect("parse");
        assert!(parsed.fixed_versions.is_empty());
    }

    /// Holds each GET until `release` is true, and records the peak in-flight count.
    #[derive(Clone)]
    struct InflightClient {
        current: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        peak: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        release: tokio::sync::watch::Receiver<bool>,
    }

    #[async_trait::async_trait]
    impl HttpClient for InflightClient {
        async fn get(&self, url: &str) -> Result<HttpResponse, CoreError> {
            use std::sync::atomic::Ordering;
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let mut release = self.release.clone();
            while !*release.borrow() {
                if release.changed().await.is_err() {
                    break;
                }
            }
            self.current.fetch_sub(1, Ordering::SeqCst);
            let id = url.rsplit('/').next().unwrap_or("missing");
            Ok(HttpResponse {
                status: 200,
                body: format!(r#"{{"id":"{id}","affected":[]}}"#),
            })
        }

        async fn post_json(
            &self,
            url: &str,
            _body: &serde_json::Value,
        ) -> Result<HttpResponse, CoreError> {
            Err(CoreError::Http {
                url: url.to_string(),
                message: "post is unused".to_string(),
            })
        }

        async fn patch_json(
            &self,
            url: &str,
            _body: &serde_json::Value,
        ) -> Result<HttpResponse, CoreError> {
            Err(CoreError::Http {
                url: url.to_string(),
                message: "patch is unused".to_string(),
            })
        }

        async fn put_json(
            &self,
            url: &str,
            _body: &serde_json::Value,
        ) -> Result<HttpResponse, CoreError> {
            Err(CoreError::Http {
                url: url.to_string(),
                message: "put is unused".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn advisory_fetches_stay_at_eight_in_flight_and_keep_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let (tx, rx) = tokio::sync::watch::channel(false);
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let client = InflightClient {
            current: Arc::clone(&current),
            peak: Arc::clone(&peak),
            release: rx,
        };
        let ids: Vec<String> = (0..10).map(|index| format!("ID-{index}")).collect();
        let package = package("lodash");
        let fetch = tokio::spawn(async move {
            fetch_advisories(&client, "https://api.osv.dev", &ids, &package).await
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while current.load(Ordering::SeqCst) < OSV_VULN_CONCURRENCY {
            assert!(Instant::now() < deadline, "timed out waiting for 8 fetches");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(current.load(Ordering::SeqCst), OSV_VULN_CONCURRENCY);
        assert_eq!(peak.load(Ordering::SeqCst), OSV_VULN_CONCURRENCY);
        tx.send(true).expect("release fetches");
        let advisories = fetch.await.expect("join").expect("fetch");
        let got: Vec<&str> = advisories.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(
            got,
            vec!["ID-0", "ID-1", "ID-2", "ID-3", "ID-4", "ID-5", "ID-6", "ID-7", "ID-8", "ID-9"]
        );
    }
}
