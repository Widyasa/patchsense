//! `patchsense init` in a temporary directory.

use assert_cmd::Command;
use patchsense_core::config::{parse_config_str, FailOn};
use patchsense_core::model::Ecosystem;
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
