//! `tools/call` for the scan tools, against a local OSV stand-in.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
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

struct Session {
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
    child: std::process::Child,
    stderr: Arc<Mutex<String>>,
}

impl Session {
    fn spawn(server: &MockServer, cache_dir: &std::path::Path) -> Self {
        let mut command = Command::cargo_bin("patchsense").expect("binary");
        command
            .arg("mcp")
            .env("PATCHSENSE_OSV_URL", server.uri())
            .env("PATCHSENSE_EPSS_URL", server.uri())
            .env(
                "PATCHSENSE_KEV_URL",
                format!("{}/kev.json", server.uri().trim_end_matches('/')),
            )
            .env("PATCHSENSE_CACHE_DIR", cache_dir)
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let stderr = child.stderr.take().expect("stderr");
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr_log = Arc::new(Mutex::new(String::new()));
        let log = Arc::clone(&stderr_log);
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let mut guard = log.lock().expect("stderr lock");
                guard.push_str(&line);
                guard.push('\n');
            }
        });
        Self {
            stdin,
            lines,
            child,
            stderr: stderr_log,
        }
    }

    fn request(&mut self, id: u64, body: &str) -> String {
        writeln!(self.stdin, "{body}").expect("write");
        self.stdin.flush().expect("flush");
        let needle_a = format!("\"id\":{id}");
        let needle_b = format!("\"id\": {id}");
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            match self.lines.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(line)) => {
                    let matched = line.contains(&needle_a) || line.contains(&needle_b);
                    seen.push(line);
                    if matched {
                        return seen.last().expect("just pushed").clone();
                    }
                }
                Ok(Err(err)) => panic!("stdout read failed: {err}"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let stderr = self.stderr.lock().expect("stderr lock").clone();
        panic!(
            "timed out waiting for id {id}\nstdout:\n{}\nstderr:\n{stderr}",
            seen.join("\n")
        );
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn tools_call_scan_finding_fix_plan_and_explain() {
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
    Mock::given(method("GET"))
        .and(path("/data/v1/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "catalogVersion": "test",
            "vulnerabilities": []
        })))
        .mount(&server)
        .await;

    let cache = tempfile::tempdir().expect("cache");
    let mut session = Session::spawn(&server, cache.path());
    let init = session.request(
        1,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"patchsense-test","version":"0"}}}"#,
    );
    assert!(
        init.contains("\"protocolVersion\":\"2025-11-25\""),
        "{init}"
    );
    writeln!(
        session.stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .expect("initialized");

    let project = repo_path("../../tests/fixtures/npm/lodash");
    let scan = session.request(
        2,
        &format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"scan_project","arguments":{{"path":"{}"}}}}}}"#,
            project.display()
        ),
    );
    assert!(!scan.contains("\"isError\":true"), "{scan}");
    assert!(scan.contains("GHSA-35jh-r3h4-6jhm"), "{scan}");
    assert!(scan.contains("schema_version"), "{scan}");
    assert!(scan.contains("4.17.21"), "{scan}");

    let finding = session.request(
        3,
        &format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"get_finding","arguments":{{"id":"GHSA-35jh-r3h4-6jhm","path":"{}"}}}}}}"#,
            project.display()
        ),
    );
    assert!(!finding.contains("\"isError\":true"), "{finding}");
    assert!(finding.contains("CVE-2021-23337"), "{finding}");
    assert!(finding.contains("4.17.21"), "{finding}");

    let plan = session.request(
        4,
        &format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"get_fix_plan","arguments":{{"path":"{}"}}}}}}"#,
            project.display()
        ),
    );
    assert!(!plan.contains("\"isError\":true"), "{plan}");
    assert!(plan.contains("npm install lodash@4.17.21"), "{plan}");
    assert!(plan.contains("GHSA-35jh-r3h4-6jhm"), "{plan}");

    let explain = session.request(
        5,
        &format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"explain_score","arguments":{{"id":"CVE-2021-23337","path":"{}"}}}}}}"#,
            project.display()
        ),
    );
    assert!(!explain.contains("\"isError\":true"), "{explain}");
    assert!(explain.contains("GHSA-35jh-r3h4-6jhm"), "{explain}");
    assert!(explain.contains("score"), "{explain}");
    assert!(explain.contains("CVSS"), "{explain}");
    assert!(explain.contains("critical threshold"), "{explain}");
}
