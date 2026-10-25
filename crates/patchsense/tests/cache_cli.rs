//! `patchsense cache` against a temporary directory. No network.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cache_info_and_clear_use_the_env_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut info = Command::cargo_bin("patchsense").expect("binary");
    info.arg("cache")
        .arg("info")
        .env("PATCHSENSE_CACHE_DIR", dir.path())
        .env_remove("XDG_CACHE_HOME");
    info.assert()
        .success()
        .stdout(predicate::str::contains("status: absent"))
        .stdout(predicate::str::contains("cache.db"));

    let mut clear = Command::cargo_bin("patchsense").expect("binary");
    clear
        .arg("cache")
        .arg("clear")
        .env("PATCHSENSE_CACHE_DIR", dir.path());
    clear
        .assert()
        .success()
        .stdout(predicate::str::contains("no cache"));
}
