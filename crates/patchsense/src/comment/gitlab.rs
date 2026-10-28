//! GitLab merge-request note upsert.

use anyhow::Context;
use serde_json::{json, Value};

use patchsense::http::{HttpClient, HttpResponse};

use super::{contains_marker, CommentOutcome};

/// GitLab coordinates for one merge request.
pub struct GitLabTarget {
    /// Project access token. Not printed.
    pub token: String,
    /// `CI_API_V4_URL`, for example `https://gitlab.com/api/v4`.
    pub api_url: String,
    /// `CI_PROJECT_ID`. Encoded into the URL.
    pub project_id: String,
    /// `CI_MERGE_REQUEST_IID`.
    pub merge_request_iid: u64,
}

/// Read the GitLab CI variables the Notes API needs.
pub fn target_from_env() -> anyhow::Result<GitLabTarget> {
    let token = std::env::var("GITLAB_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
        .context(
            "GITLAB_TOKEN is empty; a project access token with the api scope is required to comment on a merge request",
        )?;
    let api_url = std::env::var("CI_API_V4_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .context("CI_API_V4_URL is empty; expected the GitLab API v4 base URL")?;
    let project_id = std::env::var("CI_PROJECT_ID")
        .ok()
        .filter(|value| !value.is_empty())
        .context("CI_PROJECT_ID is empty")?;
    let iid = std::env::var("CI_MERGE_REQUEST_IID")
        .ok()
        .filter(|value| !value.is_empty())
        .context("CI_MERGE_REQUEST_IID is empty")?;
    let merge_request_iid = iid
        .parse::<u64>()
        .context("CI_MERGE_REQUEST_IID is not a number")?;
    Ok(GitLabTarget {
        token,
        api_url,
        project_id,
        merge_request_iid,
    })
}

/// Create a note, or edit the first note that already contains the marker.
pub async fn upsert(
    client: &dyn HttpClient,
    target: &GitLabTarget,
    markdown: &str,
) -> anyhow::Result<CommentOutcome> {
    let notes = notes_url(target);
    let listed = client.get(&format!("{notes}?per_page=100")).await?;
    if listed.status == 403 {
        return Ok(CommentOutcome::Forbidden);
    }
    ensure_success(&listed, "listing GitLab notes")?;
    let notes_json: Vec<Value> =
        serde_json::from_str(&listed.body).context("GitLab note list is not JSON")?;
    let existing = notes_json
        .into_iter()
        .find(|note| note["body"].as_str().is_some_and(contains_marker));
    let payload = json!({ "body": markdown });
    if let Some(note) = existing {
        let id = note["id"].as_u64().context("GitLab note is missing id")?;
        let updated = client.put_json(&format!("{notes}/{id}"), &payload).await?;
        if updated.status == 403 {
            return Ok(CommentOutcome::Forbidden);
        }
        ensure_success(&updated, "updating the GitLab note")?;
        return Ok(CommentOutcome::Updated(id));
    }
    let created = client.post_json(&notes, &payload).await?;
    if created.status == 403 {
        return Ok(CommentOutcome::Forbidden);
    }
    ensure_success(&created, "creating the GitLab note")?;
    let body: Value =
        serde_json::from_str(&created.body).context("GitLab create response is not JSON")?;
    Ok(CommentOutcome::Created(body["id"].as_u64().unwrap_or(0)))
}

fn notes_url(target: &GitLabTarget) -> String {
    format!(
        "{}/projects/{}/merge_requests/{}/notes",
        target.api_url.trim_end_matches('/'),
        encode_component(&target.project_id),
        target.merge_request_iid
    )
}

fn encode_component(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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
    use super::*;
    use patchsense::http::{FakeHttp, HttpResponse};
    use patchsense::report::markdown::MARKER;

    fn target() -> GitLabTarget {
        GitLabTarget {
            token: "secret".to_string(),
            api_url: "https://gitlab.test/api/v4".to_string(),
            project_id: "group/demo".to_string(),
            merge_request_iid: 4,
        }
    }

    fn markdown(text: &str) -> String {
        format!("{MARKER}\n{text}\n")
    }

    #[tokio::test]
    async fn creates_a_note_when_none_exist() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 200,
                body: "[]".to_string(),
            },
            HttpResponse {
                status: 201,
                body: r#"{"id":3}"#.to_string(),
            },
        ]);
        let probe = fake.clone();
        let outcome = upsert(&fake, &target(), &markdown("first"))
            .await
            .expect("create");
        assert_eq!(outcome, CommentOutcome::Created(3));
        let calls = probe.recorded();
        assert_eq!(calls[0].method, "GET");
        assert!(calls[0]
            .url
            .contains("/projects/group%2Fdemo/merge_requests/4/notes"));
        assert_eq!(calls[1].method, "POST");
        assert!(calls[1].body.contains(MARKER));
    }

    #[tokio::test]
    async fn edits_the_existing_marker_note() {
        let fake = FakeHttp::script(vec![
            HttpResponse {
                status: 200,
                body: format!(r#"[{{"id":8,"body":"{MARKER}\nold"}}]"#),
            },
            HttpResponse {
                status: 200,
                body: r#"{"id":8}"#.to_string(),
            },
        ]);
        let probe = fake.clone();
        let outcome = upsert(&fake, &target(), &markdown("fresh"))
            .await
            .expect("update");
        assert_eq!(outcome, CommentOutcome::Updated(8));
        let calls = probe.recorded();
        assert_eq!(calls[1].method, "PUT");
        assert!(calls[1].url.ends_with("/notes/8"));
        assert!(calls[1].body.contains("fresh"));
    }
}
