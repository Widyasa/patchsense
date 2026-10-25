//! GitHub issue-comment upsert. The hidden marker decides create versus edit.

use anyhow::Context;
use serde_json::{json, Value};

use patchsense_core::http::{HttpClient, HttpResponse};

use super::{contains_marker, CommentOutcome};

/// GitHub coordinates for one pull request. The token stays off the log path.
pub struct GitHubTarget {
    /// Personal or Actions token. Not printed.
    pub token: String,
    /// `https://api.github.com` or a `GITHUB_API_URL` override.
    pub api_url: String,
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Pull request number.
    pub pr: u64,
}

/// Read `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_API_URL`, and `GITHUB_EVENT_PATH`.
pub fn target_from_env() -> anyhow::Result<GitHubTarget> {
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .context(
            "GITHUB_TOKEN is empty; comment needs a token that can write pull request comments",
        )?;
    let repository = std::env::var("GITHUB_REPOSITORY")
        .ok()
        .filter(|value| !value.is_empty())
        .context("GITHUB_REPOSITORY is empty; expected owner/repo")?;
    let (owner, repo) = split_repository(&repository)?;
    let api_url =
        std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_string());
    let event_path = std::env::var("GITHUB_EVENT_PATH")
        .ok()
        .filter(|value| !value.is_empty())
        .context("GITHUB_EVENT_PATH is empty; expected the GitHub event payload")?;
    let event = std::fs::read_to_string(&event_path)
        .with_context(|| format!("failed to read {event_path}"))?;
    let pr = pr_number_from_event(&event)?;
    Ok(GitHubTarget {
        token,
        api_url,
        owner,
        repo,
        pr,
    })
}

/// `owner/repo` with exactly one slash.
pub fn split_repository(repository: &str) -> anyhow::Result<(String, String)> {
    let (owner, repo) = repository
        .split_once('/')
        .context("GITHUB_REPOSITORY must look like owner/repo")?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        anyhow::bail!("GITHUB_REPOSITORY must look like owner/repo");
    }
    Ok((owner.to_string(), repo.to_string()))
}

/// Pull request number from a GitHub event payload.
pub fn pr_number_from_event(text: &str) -> anyhow::Result<u64> {
    let value: Value = serde_json::from_str(text).context("GITHUB_EVENT_PATH is not JSON")?;
    value
        .pointer("/pull_request/number")
        .and_then(Value::as_u64)
        .or_else(|| value.pointer("/issue/number").and_then(Value::as_u64))
        .or_else(|| value.get("number").and_then(Value::as_u64))
        .context("GITHUB_EVENT_PATH has no pull request number")
}

/// Create a comment, or edit the first one that already contains the marker.
pub async fn upsert(
    client: &dyn HttpClient,
    target: &GitHubTarget,
    markdown: &str,
) -> anyhow::Result<CommentOutcome> {
    let list_url = format!(
        "{}/repos/{}/{}/issues/{}/comments?per_page=100",
        target.api_url.trim_end_matches('/'),
        target.owner,
        target.repo,
        target.pr
    );
    let listed = client.get(&list_url).await?;
    if listed.status == 403 {
        return Ok(CommentOutcome::Forbidden);
    }
    ensure_success(&listed, "listing GitHub comments")?;
    let comments: Vec<Value> =
        serde_json::from_str(&listed.body).context("GitHub comment list is not JSON")?;
    let existing = comments
        .into_iter()
        .find(|comment| comment["body"].as_str().is_some_and(contains_marker));
    let payload = json!({ "body": markdown });
    if let Some(comment) = existing {
        let id = comment["id"]
            .as_u64()
            .context("GitHub comment is missing id")?;
        let url = format!(
            "{}/repos/{}/{}/issues/comments/{id}",
            target.api_url.trim_end_matches('/'),
            target.owner,
            target.repo
        );
        let updated = client.patch_json(&url, &payload).await?;
        if updated.status == 403 {
            return Ok(CommentOutcome::Forbidden);
        }
        ensure_success(&updated, "updating the GitHub comment")?;
        return Ok(CommentOutcome::Updated(id));
    }
    let create_url = format!(
        "{}/repos/{}/{}/issues/{}/comments",
        target.api_url.trim_end_matches('/'),
        target.owner,
        target.repo,
        target.pr
    );
    let created = client.post_json(&create_url, &payload).await?;
    if created.status == 403 {
        return Ok(CommentOutcome::Forbidden);
    }
    ensure_success(&created, "creating the GitHub comment")?;
    let body: Value =
        serde_json::from_str(&created.body).context("GitHub create response is not JSON")?;
    let id = body["id"].as_u64().unwrap_or(0);
    Ok(CommentOutcome::Created(id))
}

fn ensure_success(response: &HttpResponse, action: &str) -> anyhow::Result<()> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        let snippet: String = response.body.chars().take(180).collect();
        anyhow::bail!("{action} failed with HTTP {}: {snippet}", response.status)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use patchsense_core::http::FakeHttp;
    use patchsense_core::report::markdown::MARKER;

    fn target() -> GitHubTarget {
        GitHubTarget {
            token: "secret".to_string(),
            api_url: "https://api.github.test".to_string(),
            owner: "acme".to_string(),
            repo: "demo".to_string(),
            pr: 7,
        }
    }

    fn markdown(text: &str) -> String {
        format!("{MARKER}\n{text}\n")
    }

    #[test]
    fn event_payload_uses_the_pull_request_number() {
        let number = pr_number_from_event(r#"{"pull_request":{"number":42}}"#).expect("pr");
        assert_eq!(number, 42);
        assert!(split_repository("acme/demo").is_ok());
        assert!(split_repository("acme").is_err());
    }

    #[tokio::test]
    async fn creates_a_comment_when_none_exist() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 200,
                body: "[]".to_string(),
            },
            HttpResponse {
                status: 201,
                body: r#"{"id":15}"#.to_string(),
            },
        ]);
        let probe = fake.clone();
        let outcome = upsert(&fake, &target(), &markdown("first"))
            .await
            .expect("create");
        assert_eq!(outcome, CommentOutcome::Created(15));
        let calls = probe.recorded();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[1].method, "POST");
        assert!(calls[1].body.contains(MARKER));
        assert!(calls[1].url.ends_with("/issues/7/comments"));
    }

    #[tokio::test]
    async fn edits_the_existing_marker_comment() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 200,
                body: format!(r#"[{{"id":9,"body":"{MARKER}\nold"}}]"#),
            },
            HttpResponse {
                status: 200,
                body: r#"{"id":9}"#.to_string(),
            },
        ]);
        let probe = fake.clone();
        let outcome = upsert(&fake, &target(), &markdown("fresh"))
            .await
            .expect("update");
        assert_eq!(outcome, CommentOutcome::Updated(9));
        let calls = probe.recorded();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].method, "PATCH");
        assert!(calls[1].url.ends_with("/issues/comments/9"));
        assert!(calls[1].body.contains("fresh"));
    }

    #[tokio::test]
    async fn second_upsert_does_not_create_a_duplicate() {
        let comments = Arc::new(Mutex::new(Vec::<Value>::new()));
        let store = comments.clone();
        let fake = FakeHttp::with_handler(move |request| {
            if request.method == "GET" {
                let list = store.lock().expect("comments").clone();
                return HttpResponse {
                    status: 200,
                    body: serde_json::to_string(&list).expect("list"),
                };
            }
            let body: Value = serde_json::from_str(&request.body).unwrap_or(json!({}));
            let text = body["body"].as_str().unwrap_or("").to_string();
            if request.method == "POST" {
                let mut list = store.lock().expect("comments");
                let id = (list.len() as u64) + 1;
                list.push(json!({"id": id, "body": text}));
                return HttpResponse {
                    status: 201,
                    body: format!(r#"{{"id":{id}}}"#),
                };
            }
            if request.method == "PATCH" {
                let id = request
                    .url
                    .rsplit('/')
                    .next()
                    .and_then(|part| part.parse::<u64>().ok());
                let mut list = store.lock().expect("comments");
                for comment in list.iter_mut() {
                    if comment["id"].as_u64() == id {
                        comment["body"] = json!(text);
                    }
                }
                return HttpResponse {
                    status: 200,
                    body: "{}".to_string(),
                };
            }
            HttpResponse {
                status: 500,
                body: request.method.clone(),
            }
        });
        upsert(&fake, &target(), &markdown("first"))
            .await
            .expect("create");
        let outcome = upsert(&fake, &target(), &markdown("second"))
            .await
            .expect("update");
        assert_eq!(outcome, CommentOutcome::Updated(1));
        let list = comments.lock().expect("comments");
        assert_eq!(list.len(), 1);
        assert!(list[0]["body"].as_str().unwrap().contains("second"));
    }

    #[tokio::test]
    async fn fork_forbidden_is_not_an_error() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 200,
                body: "[]".to_string(),
            },
            HttpResponse {
                status: 403,
                body: "Resource not accessible by integration".to_string(),
            },
        ]);
        let outcome = upsert(&fake, &target(), &markdown("hidden"))
            .await
            .expect("403");
        assert_eq!(outcome, CommentOutcome::Forbidden);
    }
}
