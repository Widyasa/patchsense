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

async fn mount_empty_enrichment(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/data/v1/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "catalogVersion": "test",
            "vulnerabilities": []
        })))
        .mount(server)
        .await;
}

fn enrichment_env(command: &mut Command, server: &MockServer) {
    command.env("PATCHSENSE_EPSS_URL", server.uri());
    command.env(
        "PATCHSENSE_KEV_URL",
        format!("{}/kev.json", server.uri().trim_end_matches('/')),
    );
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
    mount_empty_enrichment(&server).await;

    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg("--no-cache")
        .arg(repo_path("../../tests/fixtures/npm/lodash"))
        .env("PATCHSENSE_OSV_URL", server.uri())
        .env("NO_COLOR", "1");
    enrichment_env(&mut command, &server);
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

#[tokio::test]
async fn broken_lockfile_beside_a_valid_one_warns_and_exits_0() {
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
    mount_empty_enrichment(&server).await;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("a-bad")).expect("dir");
    std::fs::create_dir(dir.path().join("b-good")).expect("dir");
    std::fs::write(dir.path().join("a-bad/package-lock.json"), "{").expect("bad");
    std::fs::write(
        dir.path().join("b-good/package-lock.json"),
        r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
    )
    .expect("good");

    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg("--no-cache")
        .arg(dir.path())
        .env("PATCHSENSE_OSV_URL", server.uri())
        .env("NO_COLOR", "1");
    enrichment_env(&mut command, &server);
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("lodash@4.17.14"))
        .stderr(predicate::str::contains("a-bad/package-lock.json"));
}

#[tokio::test]
async fn every_broken_lockfile_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("a")).expect("dir");
    std::fs::create_dir(dir.path().join("b")).expect("dir");
    std::fs::write(dir.path().join("a/package-lock.json"), "{").expect("bad");
    std::fs::write(dir.path().join("b/package-lock.json"), "[]").expect("bad");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg(dir.path())
        .env("PATCHSENSE_OSV_URL", "http://127.0.0.1:9")
        .env("NO_COLOR", "1");
    command
        .assert()
        .code(2)
        .stderr(predicate::str::contains("package-lock.json"));
}

#[tokio::test]
async fn no_keep_going_exits_2_when_one_file_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("a-bad")).expect("dir");
    std::fs::create_dir(dir.path().join("b-good")).expect("dir");
    std::fs::write(dir.path().join("a-bad/package-lock.json"), "{").expect("bad");
    std::fs::write(
        dir.path().join("b-good/package-lock.json"),
        r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
    )
    .expect("good");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg("--no-keep-going")
        .arg(dir.path())
        .env("PATCHSENSE_OSV_URL", "http://127.0.0.1:9")
        .env("NO_COLOR", "1");
    command
        .assert()
        .code(2)
        .stderr(predicate::str::contains("a-bad/package-lock.json"));
}

#[tokio::test]
async fn ecosystem_filter_and_unknown_ecosystem() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
    )
    .expect("lock");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg(dir.path())
        .arg("--ecosystem")
        .arg("pypi")
        .env("PATCHSENSE_OSV_URL", "http://127.0.0.1:9")
        .env("NO_COLOR", "1");
    command
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg(dir.path())
        .arg("--ecosystem")
        .arg("not-an-ecosystem")
        .env("NO_COLOR", "1");
    command
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown ecosystem"));
}

#[tokio::test]
async fn kev_advisory_fails_critical_and_passes_never() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [{
                    "id": "GHSA-kev0-0000-0000",
                    "modified": "2026-01-01T00:00:00Z"
                }]
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-kev0-0000-0000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "GHSA-kev0-0000-0000",
            "aliases": ["CVE-2021-23337"],
            "summary": "Known exploited lodash",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }],
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]
                }]
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/data/v1/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "cve": "CVE-2021-23337",
                "epss": "0.20",
                "percentile": "0.90",
                "date": "2026-10-24"
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "catalogVersion": "test",
            "vulnerabilities": [{
                "cveID": "CVE-2021-23337",
                "dateAdded": "2021-11-03",
                "dueDate": "2021-11-17",
                "knownRansomwareCampaignUse": "Known",
                "vulnerabilityName": "Lodash Command Injection",
                "requiredAction": "Apply updates"
            }]
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.14"}}}"#,
    )
    .expect("lock");

    let mut critical = Command::cargo_bin("patchsense").expect("binary");
    critical
        .arg("scan")
        .arg("--no-cache")
        .arg(dir.path())
        .arg("--fail-on")
        .arg("critical")
        .env("PATCHSENSE_OSV_URL", server.uri())
        .env("NO_COLOR", "1");
    enrichment_env(&mut critical, &server);
    critical.assert().code(1);

    let mut never = Command::cargo_bin("patchsense").expect("binary");
    never
        .arg("scan")
        .arg("--no-cache")
        .arg(dir.path())
        .arg("--fail-on")
        .arg("never")
        .env("PATCHSENSE_OSV_URL", server.uri())
        .env("NO_COLOR", "1");
    enrichment_env(&mut never, &server);
    never.assert().success();
}

#[test]
fn invalid_config_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("patchsense.toml");
    std::fs::write(&config, "not_a_field = true\n").expect("config");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg("--config")
        .arg(&config)
        .arg(dir.path())
        .env("NO_COLOR", "1");
    command
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not_a_field"));
}
