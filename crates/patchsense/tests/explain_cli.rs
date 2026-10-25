//! `scan --explain` with a fake agent on `PATH`. Nothing calls a real agent.

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

async fn mount_osv(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(querybatch_body)
        .mount(server)
        .await;
    let advisory = std::fs::read_to_string(repo_path(
        "../../tests/fixtures/osv/vulns/GHSA-35jh-r3h4-6jhm.json",
    ))
    .expect("advisory");
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-35jh-r3h4-6jhm"))
        .respond_with(ResponseTemplate::new(200).set_body_string(advisory))
        .mount(server)
        .await;
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

fn install_codex(dir: &std::path::Path, unix_body: &str, windows_body: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = windows_body;
        let path = dir.join("codex");
        std::fs::write(&path, unix_body).expect("script");
        let mut perms = std::fs::metadata(&path).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
    }
    #[cfg(windows)]
    {
        let _ = unix_body;
        std::fs::write(dir.join("codex.bat"), windows_body).expect("script");
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (unix_body, windows_body);
    }
}

fn scan(server: &MockServer, path_dir: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .arg("scan")
        .arg("--no-cache")
        .arg("--fail-on")
        .arg("never")
        .arg("--format")
        .arg("json")
        .arg("--explain")
        .arg("--agent")
        .arg("codex")
        .arg(repo_path("../../tests/fixtures/npm/lodash"))
        .env("PATCHSENSE_OSV_URL", server.uri())
        .env("PATCHSENSE_EPSS_URL", server.uri())
        .env(
            "PATCHSENSE_KEV_URL",
            format!("{}/kev.json", server.uri().trim_end_matches('/')),
        )
        .env("PATCHSENSE_CACHE_DIR", path_dir)
        .env("PATH", std::env::join_paths([path_dir]).expect("path"))
        .env_remove("PATCHSENSE_AGENT")
        .env("NO_COLOR", "1");
    command
}

#[tokio::test]
async fn explain_inserts_the_fake_agent_text_and_exits_0() {
    let server = MockServer::start().await;
    mount_osv(&server).await;
    let dir = tempfile::tempdir().expect("temp");
    install_codex(
        dir.path(),
        "#!/bin/sh\nprintf '%s\\n' 'Upgrade lodash to 4.17.21.'\n",
        "@echo Upgrade lodash to 4.17.21.\r\n",
    );
    scan(&server, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Penjelasan AI, bisa keliru"))
        .stdout(predicate::str::contains("Upgrade lodash to 4.17.21."))
        .stdout(predicate::str::contains("\"status\": \"ok\""));
}

#[tokio::test]
async fn explain_without_an_agent_warns_and_still_exits_0() {
    let server = MockServer::start().await;
    mount_osv(&server).await;
    let dir = tempfile::tempdir().expect("temp");
    scan(&server, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\": 1"))
        .stdout(predicate::str::contains("no_agent_found"))
        .stderr(predicate::str::contains("no agent found"));
}

#[tokio::test]
async fn explain_timeout_warns_and_still_exits_0() {
    let server = MockServer::start().await;
    mount_osv(&server).await;
    let dir = tempfile::tempdir().expect("temp");
    install_codex(
        dir.path(),
        "#!/bin/sh\nexec /bin/sleep 30\n",
        "@echo off\r\n%SystemRoot%\\System32\\ping.exe -n 31 127.0.0.1 >nul\r\n",
    );
    let config = dir.path().join("patchsense.toml");
    std::fs::write(&config, "[explain]\ntimeout_secs = 1\nagent = \"codex\"\n").expect("config");
    let mut command = scan(&server, dir.path());
    command.arg("--config").arg(&config);
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"timeout\""))
        .stderr(predicate::str::contains("timed out"));
}
