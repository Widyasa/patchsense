//! `patchsense scan` against a local OSV stand-in. Nothing leaves the machine.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn querybatch_body(request: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&request.body).unwrap_or(json!({}));
    let queries = body["queries"].as_array().cloned().unwrap_or_default();
    let results: Vec<Value> = queries
        .iter()
        .map(|query| {
            if query["package"]["name"] == "lodash" {
                json!({
                    "vulns": [{
                        "id": "GHSA-35jh-r3h4-6jhm",
                        "modified": "2024-01-01T00:00:00Z"
                    }]
                })
            } else {
                json!({})
            }
        })
        .collect();
    ResponseTemplate::new(200).set_body_json(json!({ "results": results }))
}

#[tokio::test]
async fn scan_prints_lodash_advisory_from_the_npm_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(querybatch_body)
        .mount(&server)
        .await;
    let advisory = std::fs::read_to_string(repo_path(
        "../../tests/fixtures/osv/vulns/GHSA-35jh-r3h4-6jhm.json",
    ))
    .expect("advisory fixture");
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-35jh-r3h4-6jhm"))
        .respond_with(ResponseTemplate::new(200).set_body_string(advisory))
        .mount(&server)
        .await;

    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg(repo_path("../../tests/fixtures/npm/lodash"))
        .env("PATCHSENSE_OSV_URL", server.uri())
        .env("NO_COLOR", "1");
    command
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "package-lock.json  lodash@4.17.14  GHSA-35jh-r3h4-6jhm",
        ))
        .stdout(predicate::str::contains("aliases=CVE-2021-23337"))
        .stdout(predicate::str::contains("fixed=4.17.21"))
        .stdout(predicate::str::contains("Command Injection in lodash"));
}

#[tokio::test]
async fn scan_without_a_lockfile_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg(dir.path())
        .env("PATCHSENSE_OSV_URL", "http://127.0.0.1:9")
        .env("NO_COLOR", "1");
    command
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no supported lockfile"));
}
