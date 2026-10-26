//! `patchsense comment` against a local GitHub stand-in, plus dry-run.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn gitlab_without_a_token_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = dir.path().join("report.json");
    std::fs::write(&report, empty_report()).expect("report");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("comment")
        .arg("--provider")
        .arg("gitlab")
        .arg("--report")
        .arg(&report)
        .env_remove("GITLAB_TOKEN")
        .env("CI_API_V4_URL", "http://127.0.0.1:9/api/v4")
        .env("CI_PROJECT_ID", "1")
        .env("CI_MERGE_REQUEST_IID", "1");
    command
        .assert()
        .code(2)
        .stderr(predicate::str::contains("GITLAB_TOKEN"));
}

fn empty_report() -> &'static str {
    r#"{"schema_version":1,"summary":{"packages_scanned":0,"findings":0,"by_tier":{"critical":0,"review":0,"defer":0},"max_score":0,"failed":false},"findings":[]}"#
}

#[test]
fn dry_run_prints_markdown_without_a_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = dir.path().join("report.json");
    std::fs::write(&report, empty_report()).expect("report");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("comment")
        .arg("--dry-run")
        .arg("--provider")
        .arg("github")
        .arg("--report")
        .arg(&report)
        .env_remove("GITHUB_TOKEN");
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("<!-- patchsense-report -->"))
        .stdout(predicate::str::contains("No vulnerabilities"));
}

#[tokio::test]
async fn fork_pull_request_403_warns_and_exits_0() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/demo/issues/7/comments"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/demo/issues/7/comments"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Resource not accessible"))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let report = dir.path().join("report.json");
    std::fs::write(&report, empty_report()).expect("report");
    let event = dir.path().join("event.json");
    std::fs::write(&event, r#"{"pull_request":{"number":7}}"#).expect("event");

    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("comment")
        .arg("--provider")
        .arg("github")
        .arg("--report")
        .arg(&report)
        .env("GITHUB_TOKEN", "test-token")
        .env("GITHUB_REPOSITORY", "acme/demo")
        .env("GITHUB_API_URL", server.uri())
        .env("GITHUB_EVENT_PATH", &event);
    command
        .assert()
        .success()
        .stderr(predicate::str::contains("403"));
    server.verify().await;
}
