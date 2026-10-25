//! OSV query client.
//!
//! `querybatch` is chunked at [`OSV_BATCH_SIZE`]. A result with
//! `next_page_token` is queried again by itself until the token is gone.
//! The returned vectors line up with the input packages.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::CoreError;
use crate::http::{join_url, HttpClient, HttpResponse};
use crate::model::Package;

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
}
