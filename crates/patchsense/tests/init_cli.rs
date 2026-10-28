//! `patchsense init` in a temporary directory.

use assert_cmd::Command;
use patchsense::config::{parse_config_str, FailOn};
use patchsense::model::Ecosystem;
use predicates::prelude::*;

#[test]
fn init_writes_a_parseable_config_and_does_not_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("patchsense.toml");

    let mut create = Command::cargo_bin("patchsense").expect("binary");
    create.current_dir(dir.path()).arg("init");
    create
        .assert()
        .success()
        .stdout(predicate::str::contains("wrote patchsense.toml"));

    let created = std::fs::read_to_string(&path).expect("created");
    let config = parse_config_str(&path, &created).expect("parse created config");
    assert_eq!(config.schema_version, 1);
    assert_eq!(config.scan.ecosystems, Ecosystem::all().to_vec());
    assert_eq!(config.scan.fail_on, FailOn::Critical);
    assert_eq!(config.output.top, 20);

    let custom = "schema_version = 1\n[scan]\nfail_on = \"never\"\n";
    std::fs::write(&path, custom).expect("custom");

    let mut keep = Command::cargo_bin("patchsense").expect("binary");
    keep.current_dir(dir.path()).arg("init");
    keep.assert()
        .success()
        .stdout(predicate::str::contains("already exists"));
    assert_eq!(std::fs::read_to_string(&path).expect("kept"), custom);

    let mut force = Command::cargo_bin("patchsense").expect("binary");
    force.current_dir(dir.path()).arg("init").arg("--force");
    force
        .assert()
        .success()
        .stdout(predicate::str::contains("replaced patchsense.toml"));
    let replaced = std::fs::read_to_string(&path).expect("replaced");
    let config = parse_config_str(&path, &replaced).expect("parse replaced config");
    assert_eq!(config.scan.fail_on, FailOn::Critical);
    assert!(replaced.contains("GHSA-xxxx-xxxx-xxxx"));
}

#[test]
fn agent_all_is_idempotent_and_keeps_outside_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("AGENTS.md"), "# Keep\n").expect("seed");

    let mut first = Command::cargo_bin("patchsense").expect("binary");
    first.current_dir(dir.path()).arg("init").arg("--agent");
    first.assert().success();

    let mut second = Command::cargo_bin("patchsense").expect("binary");
    second
        .current_dir(dir.path())
        .arg("init")
        .arg("--agent")
        .arg("all");
    second.assert().success();

    let agents = std::fs::read_to_string(dir.path().join("AGENTS.md")).expect("agents");
    assert_eq!(agents.matches("<!-- patchsense:start -->").count(), 1);
    assert!(agents.contains("# Keep"));
    assert!(agents.contains("scan_project"));
    assert!(std::fs::read_to_string(dir.path().join("CLAUDE.md"))
        .expect("claude")
        .contains("<!-- patchsense:end -->"));
    let rule =
        std::fs::read_to_string(dir.path().join(".cursor/rules/patchsense.mdc")).expect("mdc");
    assert_eq!(rule.matches("alwaysApply: false").count(), 1);
    assert_eq!(rule.matches("<!-- patchsense:start -->").count(), 1);
}

#[test]
fn print_mcp_config_matches_the_snapshot_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut command = Command::cargo_bin("patchsense").expect("binary");
    command
        .current_dir(dir.path())
        .arg("init")
        .arg("--print-mcp-config");
    let output = command.output().expect("run");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(dir.path().read_dir().expect("dir").next().is_none());
    insta::assert_snapshot!(stdout);
}
