//! HTTP access for OSV, EPSS, and KEV.
//!
//! Production calls go through [`ReqwestClient`] (rustls, retries on 429 and
//! 5xx). Tests use [`FakeHttp`], which never opens a socket. [`FakeHttp::forbid`]
//! panics if it is called, so offline mode can prove it did not touch the network.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::CoreError;
use crate::VERSION;

/// One HTTP response. The body is UTF-8 text, which is what OSV, EPSS, and KEV return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: String,
}

impl HttpResponse {
    /// Build a response from a fixture file. Status is 200.
    pub fn from_fixture(path: &Path) -> Result<Self, CoreError> {
        let body = fs::read_to_string(path).map_err(|source| CoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self { status: 200, body })
    }
}

/// A request observed by [`FakeHttp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// `GET` or `POST`.
    pub method: String,
    /// URL the caller asked for.
    pub url: String,
    /// JSON body for POST, otherwise empty.
    pub body: String,
}

/// How many times a 429 or 5xx response is retried, and the first backoff.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Extra attempts after the first response. Default is 3.
    pub max_retries: u32,
    /// Delay before the first retry. Later retries double it. Zero skips sleeping.
    pub initial_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(200),
        }
    }
}

/// Something that can GET and POST JSON.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// HTTP GET.
    async fn get(&self, url: &str) -> Result<HttpResponse, CoreError>;

    /// HTTP POST with a JSON body and `Content-Type: application/json`.
    async fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError>;

    /// HTTP PATCH with a JSON body and `Content-Type: application/json`.
    async fn patch_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError>;

    /// HTTP PUT with a JSON body and `Content-Type: application/json`.
    async fn put_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError>;
}

/// Wraps a client and retries HTTP 429 and 5xx.
pub struct RetryingClient<C> {
    inner: C,
    policy: RetryPolicy,
}

impl<C> RetryingClient<C> {
    /// Wrap `inner` with `policy`.
    pub fn new(inner: C, policy: RetryPolicy) -> Self {
        Self { inner, policy }
    }
}

#[async_trait]
impl<C> HttpClient for RetryingClient<C>
where
    C: HttpClient,
{
    async fn get(&self, url: &str) -> Result<HttpResponse, CoreError> {
        let mut attempt = 0u32;
        loop {
            let result = self.inner.get(url).await;
            if !should_retry(&result) || attempt >= self.policy.max_retries {
                return result;
            }
            backoff(self.policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        let mut attempt = 0u32;
        loop {
            let result = self.inner.post_json(url, body).await;
            if !should_retry(&result) || attempt >= self.policy.max_retries {
                return result;
            }
            backoff(self.policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }

    async fn patch_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        let mut attempt = 0u32;
        loop {
            let result = self.inner.patch_json(url, body).await;
            if !should_retry(&result) || attempt >= self.policy.max_retries {
                return result;
            }
            backoff(self.policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }

    async fn put_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        let mut attempt = 0u32;
        loop {
            let result = self.inner.put_json(url, body).await;
            if !should_retry(&result) || attempt >= self.policy.max_retries {
                return result;
            }
            backoff(self.policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }
}

fn should_retry(result: &Result<HttpResponse, CoreError>) -> bool {
    match result {
        Ok(response) => response.status == 429 || (500..600).contains(&response.status),
        Err(_) => false,
    }
}

async fn backoff(initial: Duration, attempt: u32) {
    if initial.is_zero() {
        return;
    }
    let shift = attempt.min(4);
    let delay = initial.saturating_mul(1u32 << shift);
    tokio::time::sleep(delay).await;
}

/// reqwest client using rustls. Retries 429 and 5xx up to three times.
#[derive(Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
    policy: RetryPolicy,
}

impl ReqwestClient {
    /// Build a client with user-agent `patchsense/<version>` and a 30 second timeout.
    pub fn new() -> Result<Self, CoreError> {
        Self::build(reqwest::header::HeaderMap::new())
    }

    /// Same as [`Self::new`], plus a GitHub bearer token on every request.
    ///
    /// The header is marked sensitive so debug output does not print the token.
    pub fn with_bearer(token: &str) -> Result<Self, CoreError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            sensitive_header(&format!("Bearer {token}"))?,
        );
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
        );
        Self::build(headers)
    }

    /// Same as [`Self::new`], plus a GitLab `PRIVATE-TOKEN` header.
    pub fn with_private_token(token: &str) -> Result<Self, CoreError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static("private-token"),
            sensitive_header(token)?,
        );
        Self::build(headers)
    }

    fn build(headers: reqwest::header::HeaderMap) -> Result<Self, CoreError> {
        let client = reqwest::Client::builder()
            .user_agent(format!("patchsense/{VERSION}"))
            .timeout(Duration::from_secs(30))
            .default_headers(headers)
            .build()
            .map_err(|err| CoreError::Http {
                url: "reqwest".to_string(),
                message: format!("failed to build HTTP client: {err}"),
            })?;
        Ok(Self {
            client,
            policy: RetryPolicy::default(),
        })
    }
}

fn sensitive_header(value: &str) -> Result<reqwest::header::HeaderValue, CoreError> {
    let mut header =
        reqwest::header::HeaderValue::from_str(value).map_err(|err| CoreError::Http {
            url: "reqwest".to_string(),
            message: format!("invalid token header: {err}"),
        })?;
    header.set_sensitive(true);
    Ok(header)
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<HttpResponse, CoreError> {
        let client = self.client.clone();
        let url_owned = url.to_string();
        let policy = self.policy;
        let mut attempt = 0u32;
        loop {
            let result = send_reqwest(client.get(&url_owned), &url_owned).await;
            if !should_retry(&result) || attempt >= policy.max_retries {
                return result;
            }
            backoff(policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        let client = self.client.clone();
        let url_owned = url.to_string();
        let payload = body.clone();
        let policy = self.policy;
        let mut attempt = 0u32;
        loop {
            let result = send_reqwest(client.post(&url_owned).json(&payload), &url_owned).await;
            if !should_retry(&result) || attempt >= policy.max_retries {
                return result;
            }
            backoff(policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }

    async fn patch_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        let client = self.client.clone();
        let url_owned = url.to_string();
        let payload = body.clone();
        let policy = self.policy;
        let mut attempt = 0u32;
        loop {
            let result = send_reqwest(client.patch(&url_owned).json(&payload), &url_owned).await;
            if !should_retry(&result) || attempt >= policy.max_retries {
                return result;
            }
            backoff(policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }

    async fn put_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        let client = self.client.clone();
        let url_owned = url.to_string();
        let payload = body.clone();
        let policy = self.policy;
        let mut attempt = 0u32;
        loop {
            let result = send_reqwest(client.put(&url_owned).json(&payload), &url_owned).await;
            if !should_retry(&result) || attempt >= policy.max_retries {
                return result;
            }
            backoff(policy.initial_backoff, attempt).await;
            attempt += 1;
        }
    }
}

async fn send_reqwest(
    builder: reqwest::RequestBuilder,
    url: &str,
) -> Result<HttpResponse, CoreError> {
    let response = builder.send().await.map_err(|err| CoreError::Http {
        url: url.to_string(),
        message: err.to_string(),
    })?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(|err| CoreError::Http {
        url: url.to_string(),
        message: err.to_string(),
    })?;
    Ok(HttpResponse { status, body })
}

#[derive(Clone)]
enum FakeMode {
    Forbid,
    Sequence(Arc<Mutex<VecDeque<HttpResponse>>>),
    Handler(Arc<dyn Fn(&RecordedRequest) -> HttpResponse + Send + Sync>),
}

/// In-memory HTTP client. It records every call and never touches the network.
#[derive(Clone)]
pub struct FakeHttp {
    mode: FakeMode,
    recorded: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl FakeHttp {
    /// Return scripted responses in order. A missing response is HTTP 500.
    pub fn script(responses: Vec<HttpResponse>) -> Self {
        Self {
            mode: FakeMode::Sequence(Arc::new(Mutex::new(VecDeque::from(responses)))),
            recorded: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Build each response from the request. Used to serve fixture JSON.
    pub fn with_handler<F>(handler: F) -> Self
    where
        F: Fn(&RecordedRequest) -> HttpResponse + Send + Sync + 'static,
    {
        Self {
            mode: FakeMode::Handler(Arc::new(handler)),
            recorded: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Panic if a request is made. For `--offline` tests.
    pub fn forbid() -> Self {
        Self {
            mode: FakeMode::Forbid,
            recorded: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Calls observed so far, in order.
    pub fn recorded(&self) -> Vec<RecordedRequest> {
        self.recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn get(&self, url: &str) -> Result<HttpResponse, CoreError> {
        self.dispatch(RecordedRequest {
            method: "GET".to_string(),
            url: url.to_string(),
            body: String::new(),
        })
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        self.dispatch(RecordedRequest {
            method: "POST".to_string(),
            url: url.to_string(),
            body: body.to_string(),
        })
    }

    async fn patch_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        self.dispatch(RecordedRequest {
            method: "PATCH".to_string(),
            url: url.to_string(),
            body: body.to_string(),
        })
    }

    async fn put_json(&self, url: &str, body: &Value) -> Result<HttpResponse, CoreError> {
        self.dispatch(RecordedRequest {
            method: "PUT".to_string(),
            url: url.to_string(),
            body: body.to_string(),
        })
    }
}

impl FakeHttp {
    fn dispatch(&self, request: RecordedRequest) -> Result<HttpResponse, CoreError> {
        if matches!(self.mode, FakeMode::Forbid) {
            panic!(
                "FakeHttp::forbid was called for {} {}",
                request.method, request.url
            );
        }
        self.recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(request.clone());
        let response = match &self.mode {
            FakeMode::Forbid => unreachable!("forbid already panicked"),
            FakeMode::Sequence(queue) => {
                let mut queue = queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                queue.pop_front().unwrap_or(HttpResponse {
                    status: 500,
                    body: "FakeHttp has no more scripted responses".to_string(),
                })
            }
            FakeMode::Handler(handler) => handler(&request),
        };
        Ok(response)
    }
}

/// Base URL for the OSV API. `PATCHSENSE_OSV_URL` overrides it (no trailing slash required).
pub fn osv_base_url() -> String {
    std::env::var("PATCHSENSE_OSV_URL").unwrap_or_else(|_| "https://api.osv.dev".to_string())
}

/// Base URL for the FIRST EPSS API. `PATCHSENSE_EPSS_URL` overrides it.
pub fn epss_base_url() -> String {
    std::env::var("PATCHSENSE_EPSS_URL").unwrap_or_else(|_| "https://api.first.org".to_string())
}

/// Full URL of the CISA KEV JSON feed. `PATCHSENSE_KEV_URL` overrides it.
pub fn kev_feed_url() -> String {
    std::env::var("PATCHSENSE_KEV_URL").unwrap_or_else(|_| {
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            .to_string()
    })
}

/// Join a base URL and a path, trimming extra slashes.
pub fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn retry_uses_fake_http_without_the_network() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 429,
                body: "slow".to_string(),
            },
            HttpResponse {
                status: 503,
                body: "down".to_string(),
            },
            HttpResponse {
                status: 200,
                body: "ok".to_string(),
            },
        ]);
        let probe = fake.clone();
        let client = RetryingClient::new(
            fake,
            RetryPolicy {
                max_retries: 3,
                initial_backoff: Duration::ZERO,
            },
        );
        let response = client
            .get("https://api.osv.dev/v1/vulns/GHSA-test")
            .await
            .expect("retry should succeed");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "ok");
        let calls = probe.recorded();
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|call| call.method == "GET"));
    }

    #[tokio::test]
    async fn retry_stops_after_three_extra_attempts() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 500,
                body: "1".to_string(),
            },
            HttpResponse {
                status: 500,
                body: "2".to_string(),
            },
            HttpResponse {
                status: 500,
                body: "3".to_string(),
            },
            HttpResponse {
                status: 500,
                body: "4".to_string(),
            },
            HttpResponse {
                status: 200,
                body: "should not be reached".to_string(),
            },
        ]);
        let probe = fake.clone();
        let client = RetryingClient::new(
            fake,
            RetryPolicy {
                max_retries: 3,
                initial_backoff: Duration::ZERO,
            },
        );
        let response = client
            .post_json(
                "https://example.test/v1/querybatch",
                &json!({"queries": []}),
            )
            .await
            .expect("final 500 is still a response");
        assert_eq!(response.status, 500);
        assert_eq!(response.body, "4");
        assert_eq!(probe.recorded().len(), 4);
    }

    #[tokio::test]
    async fn forbid_panics_when_called() {
        let client = FakeHttp::forbid();
        let joined = tokio::task::spawn(async move {
            let _ = client.get("https://api.osv.dev/v1/querybatch").await;
        })
        .await;
        assert!(joined.is_err(), "FakeHttp::forbid should panic");
    }

    #[tokio::test]
    async fn handler_can_serve_a_fixture_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ok.json");
        fs::write(&path, "{\"ok\":true}").expect("write fixture");
        let fixture = HttpResponse::from_fixture(&path).expect("fixture");
        let fake = FakeHttp::with_handler(move |_| fixture.clone());
        let response = fake.get("http://127.0.0.1/fixture").await.expect("get");
        assert_eq!(response.body, "{\"ok\":true}");
        assert_eq!(fake.recorded()[0].url, "http://127.0.0.1/fixture");
    }

    #[test]
    fn base_urls_have_defaults() {
        let osv = osv_base_url();
        let epss = epss_base_url();
        let kev = kev_feed_url();
        assert!(osv.starts_with("http"));
        assert!(epss.starts_with("http"));
        assert!(kev.starts_with("http"));
        assert_eq!(
            join_url("https://api.osv.dev/", "/v1/querybatch"),
            "https://api.osv.dev/v1/querybatch"
        );
    }
}
