//! FIRST EPSS client.
//!
//! `GET /data/v1/epss?cve=...` is split into chunks of [`EPSS_CHUNK_SIZE`].
//! `epss` and `percentile` arrive as decimal strings and are stored as `f64`.
//! Fresh cache rows are not requested again.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use crate::cache::{Cache, EpssEntry, DEFAULT_TTL};
use crate::error::CoreError;
use crate::http::{join_url, HttpClient};

/// CVEs per EPSS request. FIRST's default `limit` is 100.
pub const EPSS_CHUNK_SIZE: usize = 100;

/// Default FIRST API origin.
pub const DEFAULT_EPSS_URL: &str = "https://api.first.org";

/// `PATCHSENSE_EPSS_URL`, or [`DEFAULT_EPSS_URL`].
pub fn epss_base_url() -> String {
    std::env::var("PATCHSENSE_EPSS_URL").unwrap_or_else(|_| DEFAULT_EPSS_URL.to_string())
}

/// Fetch EPSS scores for `cves`. Cached fresh rows are not requested again.
pub async fn fetch_epss<C: HttpClient>(
    client: &C,
    base_url: &str,
    cves: &[String],
    cache: Option<&Cache>,
    now: i64,
) -> Result<BTreeMap<String, EpssEntry>, CoreError> {
    fetch_epss_ttl(client, base_url, cves, cache, now, DEFAULT_TTL).await
}

/// [`fetch_epss`] with an explicit TTL.
pub async fn fetch_epss_ttl<C: HttpClient>(
    client: &C,
    base_url: &str,
    cves: &[String],
    cache: Option<&Cache>,
    now: i64,
    ttl: Duration,
) -> Result<BTreeMap<String, EpssEntry>, CoreError> {
    let mut unique = cves.to_vec();
    unique.sort();
    unique.dedup();
    let mut scores = BTreeMap::new();
    let mut pending = Vec::new();
    for cve in unique {
        if let Some(cache) = cache {
            if let Some(entry) = cache.get_epss(&cve, now, ttl)? {
                scores.insert(cve, entry);
                continue;
            }
        }
        pending.push(cve);
    }
    for chunk in pending.chunks(EPSS_CHUNK_SIZE) {
        let url = epss_url(base_url, chunk);
        let response = client.get(&url).await?;
        if !(200..300).contains(&response.status) {
            return Err(CoreError::Http {
                url,
                message: format!("status {}", response.status),
            });
        }
        for entry in parse_epss_body(&url, &response.body, now)? {
            if let Some(cache) = cache {
                cache.put_epss(&entry)?;
            }
            scores.insert(entry.cve.clone(), entry);
        }
    }
    Ok(scores)
}

fn epss_url(base_url: &str, cves: &[String]) -> String {
    let joined = cves.join(",");
    join_url(
        base_url,
        &format!("/data/v1/epss?cve={joined}&limit={EPSS_CHUNK_SIZE}"),
    )
}

/// Parse a FIRST EPSS JSON body. `epss` and `percentile` are decimal strings.
pub fn parse_epss_body(
    url: &str,
    body: &str,
    fetched_at: i64,
) -> Result<Vec<EpssEntry>, CoreError> {
    let doc: Value =
        serde_json::from_str(body).map_err(|err| CoreError::json(url, err.to_string()))?;
    let Some(rows) = doc.get("data").and_then(Value::as_array) else {
        return Err(CoreError::json(url, "EPSS response is missing data"));
    };
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let cve = row["cve"].as_str().unwrap_or("").to_string();
        if cve.is_empty() {
            return Err(CoreError::json(url, "EPSS row is missing cve"));
        }
        let score = parse_decimal(url, &cve, "epss", row["epss"].as_str())?;
        let percentile = parse_decimal(url, &cve, "percentile", row["percentile"].as_str())?;
        let date = row["date"].as_str().unwrap_or("").to_string();
        entries.push(EpssEntry {
            cve,
            score,
            percentile,
            date,
            fetched_at,
        });
    }
    Ok(entries)
}

fn parse_decimal(url: &str, cve: &str, field: &str, raw: Option<&str>) -> Result<f64, CoreError> {
    let Some(raw) = raw else {
        return Err(CoreError::json(url, format!("{cve} is missing {field}")));
    };
    raw.parse::<f64>().map_err(|err| {
        CoreError::json(url, format!("{cve} {field} `{raw}` is not a number: {err}"))
    })
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
            .join("../../tests/fixtures/epss/first_sample.json");
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    #[test]
    fn fixture_parses_decimal_strings() {
        let rows = parse_epss_body("fixture", &fixture(), 10).expect("parse");
        assert_eq!(rows.len(), 2);
        let xz = rows
            .iter()
            .find(|row| row.cve == "CVE-2024-3094")
            .expect("xz");
        assert!((xz.score - 0.909).abs() < 1e-9, "{}", xz.score);
        assert!((xz.percentile - 0.99809).abs() < 1e-9, "{}", xz.percentile);
        assert_eq!(xz.date, "2026-10-24");
        let lodash = rows
            .iter()
            .find(|row| row.cve == "CVE-2021-23337")
            .expect("lodash");
        assert!((lodash.score - 0.21333).abs() < 1e-9, "{}", lodash.score);
    }

    #[tokio::test]
    async fn two_hundred_fifty_cves_make_three_requests() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let http = FakeHttp::with_handler(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            HttpResponse {
                status: 200,
                body: r#"{"status":"OK","data":[]}"#.to_string(),
            }
        });
        let cves: Vec<String> = (1..=250).map(|n| format!("CVE-2024-{n:05}")).collect();
        let scores = fetch_epss(&http, "https://api.first.org", &cves, None, 10)
            .await
            .expect("fetch");
        assert!(scores.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(http.recorded().len(), 3);
        assert!(http.recorded()[0].url.contains("CVE-2024-00001"));
        assert!(http.recorded()[2].url.contains("CVE-2024-00250"));
        assert!(!http.recorded()[2].url.contains("CVE-2024-00100"));
    }

    #[tokio::test]
    async fn second_fetch_uses_the_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("cache");
        let body = fixture();
        let http = FakeHttp::with_handler(move |_| HttpResponse {
            status: 200,
            body: body.clone(),
        });
        let cves = vec!["CVE-2024-3094".to_string(), "CVE-2021-23337".to_string()];
        let first = fetch_epss(&http, "https://api.first.org", &cves, Some(&cache), 1_000)
            .await
            .expect("first");
        assert_eq!(first.len(), 2);
        assert_eq!(http.recorded().len(), 1);

        let second = fetch_epss(
            &FakeHttp::forbid(),
            "https://api.first.org",
            &cves,
            Some(&cache),
            1_000,
        )
        .await
        .expect("cached");
        assert!((second["CVE-2024-3094"].score - 0.909).abs() < 1e-9);
        assert_eq!(second["CVE-2021-23337"].date, "2026-10-24");
    }
}
