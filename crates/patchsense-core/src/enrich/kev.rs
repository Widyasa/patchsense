//! CISA Known Exploited Vulnerabilities catalog.
//!
//! The feed is downloaded at most once per TTL. The cached document is the
//! whole catalog JSON, keyed by `catalogVersion` in SQLite. Lookup is a map
//! from CVE id to the fields the scorer needs.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use crate::cache::{Cache, KevEntry, DEFAULT_TTL};
use crate::error::CoreError;
use crate::http::HttpClient;

/// Official CISA feed. `PATCHSENSE_KEV_URL` may replace it in tests.
pub const DEFAULT_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// One catalog entry the scorer reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevRecord {
    /// `cveID`.
    pub cve_id: String,
    /// `dateAdded`.
    pub date_added: String,
    /// `dueDate`.
    pub due_date: String,
    /// `knownRansomwareCampaignUse` (`Known` or `Unknown`).
    pub known_ransomware_campaign_use: String,
    /// `vulnerabilityName`.
    pub vulnerability_name: String,
    /// `requiredAction`.
    pub required_action: String,
}

/// A parsed catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevCatalog {
    /// `catalogVersion`.
    pub catalog_version: String,
    /// CVE id to record.
    pub by_cve: BTreeMap<String, KevRecord>,
}

/// `PATCHSENSE_KEV_URL`, or [`DEFAULT_KEV_URL`].
pub fn kev_feed_url() -> String {
    std::env::var("PATCHSENSE_KEV_URL").unwrap_or_else(|_| DEFAULT_KEV_URL.to_string())
}

/// Load the catalog from cache when it is inside `ttl`, otherwise download it.
pub async fn fetch_kev<C: HttpClient>(
    client: &C,
    feed_url: &str,
    cache: Option<&Cache>,
    now: i64,
) -> Result<KevCatalog, CoreError> {
    fetch_kev_ttl(client, feed_url, cache, now, DEFAULT_TTL).await
}

/// [`fetch_kev`] with an explicit TTL.
pub async fn fetch_kev_ttl<C: HttpClient>(
    client: &C,
    feed_url: &str,
    cache: Option<&Cache>,
    now: i64,
    ttl: Duration,
) -> Result<KevCatalog, CoreError> {
    if let Some(cache) = cache {
        if let Some(entry) = cache.get_kev(now, ttl)? {
            return parse_kev_catalog(&entry.json);
        }
    }
    let response = client.get(feed_url).await?;
    if !(200..300).contains(&response.status) {
        return Err(CoreError::Http {
            url: feed_url.to_string(),
            message: format!("status {}", response.status),
        });
    }
    let catalog = parse_kev_catalog(&response.body)?;
    if let Some(cache) = cache {
        cache.put_kev(&KevEntry {
            catalog_version: catalog.catalog_version.clone(),
            json: response.body.clone(),
            fetched_at: now,
        })?;
    }
    Ok(catalog)
}

/// Parse a KEV catalog document into a CVE map.
pub fn parse_kev_catalog(body: &str) -> Result<KevCatalog, CoreError> {
    let doc: Value =
        serde_json::from_str(body).map_err(|err| CoreError::json("kev", err.to_string()))?;
    let catalog_version = doc["catalogVersion"].as_str().unwrap_or("").to_string();
    if catalog_version.is_empty() {
        return Err(CoreError::json("kev", "catalog is missing catalogVersion"));
    }
    let Some(rows) = doc.get("vulnerabilities").and_then(Value::as_array) else {
        return Err(CoreError::json("kev", "catalog is missing vulnerabilities"));
    };
    let mut by_cve = BTreeMap::new();
    for row in rows {
        let cve_id = row["cveID"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() {
            continue;
        }
        by_cve.insert(
            cve_id.clone(),
            KevRecord {
                cve_id,
                date_added: text(row, "dateAdded"),
                due_date: text(row, "dueDate"),
                known_ransomware_campaign_use: text(row, "knownRansomwareCampaignUse"),
                vulnerability_name: text(row, "vulnerabilityName"),
                required_action: text(row, "requiredAction"),
            },
        );
    }
    Ok(KevCatalog {
        catalog_version,
        by_cve,
    })
}

fn text(row: &Value, field: &str) -> String {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{FakeHttp, HttpResponse};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn fixture() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/kev/kev_small.json");
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    #[test]
    fn fixture_lookup_keeps_ransomware_flag() {
        let catalog = parse_kev_catalog(&fixture()).expect("parse");
        assert_eq!(catalog.catalog_version, "2026.10.23");
        assert_eq!(catalog.by_cve.len(), 2);
        let known = catalog.by_cve.get("CVE-2026-59310").expect("known");
        assert_eq!(known.known_ransomware_campaign_use, "Known");
        assert_eq!(known.date_added, "2026-08-18");
        assert_eq!(known.due_date, "2026-08-21");
        assert!(known.vulnerability_name.contains("vCenter"));
        assert!(!known.required_action.is_empty());
        let unknown = catalog.by_cve.get("CVE-2026-114625").expect("unknown");
        assert_eq!(unknown.known_ransomware_campaign_use, "Unknown");
    }

    #[tokio::test]
    async fn fresh_cache_skips_the_download_and_expired_cache_refreshes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("cache");
        let body = fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let payload = body.clone();
        let http = FakeHttp::with_handler(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            HttpResponse {
                status: 200,
                body: payload.clone(),
            }
        });
        let url =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        let ttl = Duration::from_secs(100);
        let first = fetch_kev_ttl(&http, url, Some(&cache), 1_000, ttl)
            .await
            .expect("first");
        assert_eq!(
            first.by_cve["CVE-2026-59310"].known_ransomware_campaign_use,
            "Known"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let cached = fetch_kev_ttl(&FakeHttp::forbid(), url, Some(&cache), 1_050, ttl)
            .await
            .expect("cached");
        assert_eq!(cached.catalog_version, "2026.10.23");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let refreshed = fetch_kev_ttl(&http, url, Some(&cache), 1_100, ttl)
            .await
            .expect("refresh");
        assert_eq!(refreshed.by_cve.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
