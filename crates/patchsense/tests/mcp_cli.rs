//! `patchsense mcp` speaks initialize and tools/list on stdio.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;

#[test]
fn initialize_and_tools_list_include_supported_lockfiles() {
    let mut child = Command::cargo_bin("patchsense")
        .expect("binary")
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if sender.send(line).is_err() {
                break;
            }
        }
    });

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-11-25","capabilities":{{}},"clientInfo":{{"name":"patchsense-test","version":"0"}}}}}}"#
    )
    .expect("write initialize");
    stdin.flush().expect("flush");

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut lines = Vec::new();
    let mut listed = false;
    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(Ok(line)) => {
                let is_init = line.contains("\"id\":1") || line.contains("\"id\": 1");
                lines.push(line);
                if is_init && !listed {
                    writeln!(
                        stdin,
                        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
                    )
                    .expect("write initialized");
                    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#)
                        .expect("write tools/list");
                    stdin.flush().expect("flush");
                    listed = true;
                }
                if lines
                    .iter()
                    .any(|item| item.contains("list_supported_lockfiles"))
                {
                    break;
                }
            }
            Ok(Err(err)) => panic!("stdout read failed: {err}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let joined = lines.join("\n");
    assert!(
        joined.contains("list_supported_lockfiles"),
        "stdout did not list the tool: {joined}"
    );
    assert!(
        joined.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize response missing: {joined}"
    );
}
