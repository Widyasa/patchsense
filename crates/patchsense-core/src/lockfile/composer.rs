//! Parser for Composer `composer.lock`.
//!
//! `packages` are production packages and `packages-dev` are dev packages.
//! `direct` comes from a sibling `composer.json` (`require`, `require-dev`).
//! Packagist versions sent to OSV do not use Composer's leading `v`, so
//! `v1.2.3` is stored as `1.2.3`.
//!
//! A concrete `platform` / `platform-dev` version (no constraint operator) is
//! also a package. That is how the PHP2Shell demo records PHP `8.3.35`.
//! Constraint strings such as `^8.1` are not installed versions and are skipped.
//!
//! Branch versions (`dev-main`, `8.1.x-dev`) and `dist.type` `path` packages
//! are skipped with a warning. They are not sent to OSV.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `composer.lock`.
pub struct ComposerParser;

impl LockfileParser for ComposerParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Packagist
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("composer.lock"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_composer(path, content)
    }
}

fn parse_composer(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let doc: Value = serde_json::from_str(content)
        .map_err(|err| CoreError::parse(path, Some(err.line()), err.to_string()))?;
    if !doc.is_object() {
        return Err(CoreError::parse(
            path,
            None,
            "composer.lock is not a JSON object",
        ));
    }
    let sibling = composer_json_deps(path)?;
    let source = display_path(path);
    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    push_package_list(
        &doc,
        "packages",
        false,
        &sibling,
        &source,
        &mut packages,
        &mut warnings,
    );
    push_package_list(
        &doc,
        "packages-dev",
        true,
        &sibling,
        &source,
        &mut packages,
        &mut warnings,
    );
    push_platform(&doc, "platform", false, &sibling, &source, &mut packages);
    push_platform(&doc, "platform-dev", true, &sibling, &source, &mut packages);
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    warnings.sort();
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Packagist,
        packages,
        warnings,
    })
}

fn push_package_list(
    doc: &Value,
    key: &str,
    dev_section: bool,
    sibling: &Option<ComposerJsonDeps>,
    source: &str,
    packages: &mut Vec<Package>,
    warnings: &mut Vec<String>,
) {
    let Some(list) = doc.get(key).and_then(Value::as_array) else {
        return;
    };
    for item in list {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = item.get("version").and_then(Value::as_str) else {
            continue;
        };
        if is_branch_version(version) {
            warnings.push(format!("skipped Packagist branch version {name}@{version}"));
            continue;
        }
        if is_path_package(item) {
            warnings.push(format!("skipped Packagist path package {name}@{version}"));
            continue;
        }
        packages.push(make_package(
            name,
            normalize_packagist_version(version),
            dev_section,
            sibling,
            source,
        ));
    }
}

fn is_branch_version(version: &str) -> bool {
    let version = version.trim();
    version.starts_with("dev-") || version.ends_with(".x-dev")
}

fn is_path_package(item: &Value) -> bool {
    item.get("dist")
        .and_then(|dist| dist.get("type"))
        .and_then(Value::as_str)
        == Some("path")
}

fn push_platform(
    doc: &Value,
    key: &str,
    dev_section: bool,
    sibling: &Option<ComposerJsonDeps>,
    source: &str,
    packages: &mut Vec<Package>,
) {
    let Some(table) = doc.get(key).and_then(Value::as_object) else {
        return;
    };
    for (name, version) in table {
        let Some(version) = version.as_str() else {
            continue;
        };
        if !is_concrete_version(version) {
            continue;
        }
        packages.push(make_package(
            name,
            normalize_packagist_version(version),
            dev_section,
            sibling,
            source,
        ));
    }
}

fn make_package(
    name: &str,
    version: String,
    dev_section: bool,
    sibling: &Option<ComposerJsonDeps>,
    source: &str,
) -> Package {
    let (direct, dev) = match sibling {
        None => (None, dev_section),
        Some(info) => {
            let is_dep = info.require.contains(name);
            let is_dev = info.require_dev.contains(name);
            let dev = dev_section || (is_dev && !is_dep);
            (Some(is_dep || is_dev), dev)
        }
    };
    Package {
        ecosystem: Ecosystem::Packagist,
        name: name.to_string(),
        version,
        direct,
        dev,
        source_file: source.to_string(),
        source_files: Vec::new(),
        line: None,
    }
}

/// Drop a single leading `v` when the remainder starts with a digit.
///
/// Composer stores some tags as `v1.2.3`. OSV Packagist queries use `1.2.3`.
pub(crate) fn normalize_packagist_version(version: &str) -> String {
    let trimmed = version.trim();
    if let Some(rest) = trimmed.strip_prefix('v') {
        if rest.starts_with(|ch: char| ch.is_ascii_digit()) {
            return rest.to_string();
        }
    }
    trimmed.to_string()
}

fn is_concrete_version(version: &str) -> bool {
    let version = version.trim().trim_start_matches('v');
    let Some(first) = version.chars().next() else {
        return false;
    };
    first.is_ascii_digit() && !version.contains(['^', '~', '|', '*', '<', '>', ' '])
}

struct ComposerJsonDeps {
    require: BTreeSet<String>,
    require_dev: BTreeSet<String>,
}

fn composer_json_deps(lock_path: &Path) -> Result<Option<ComposerJsonDeps>, CoreError> {
    let Some(parent) = lock_path.parent() else {
        return Ok(None);
    };
    let sibling = parent.join("composer.json");
    if !sibling.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&sibling).map_err(|source| CoreError::Io {
        path: sibling.clone(),
        source,
    })?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| CoreError::parse(sibling.clone(), Some(err.line()), err.to_string()))?;
    let mut require = BTreeSet::new();
    let mut require_dev = BTreeSet::new();
    if let Some(table) = value.get("require").and_then(Value::as_object) {
        require.extend(table.keys().cloned());
    }
    if let Some(table) = value.get("require-dev").and_then(Value::as_object) {
        require_dev.extend(table.keys().cloned());
    }
    Ok(Some(ComposerJsonDeps {
        require,
        require_dev,
    }))
}

fn display_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_fixture(project: &str) -> ParsedLockfile {
        let relative = format!("tests/fixtures/composer/{project}/composer.lock");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        let mut parsed = ComposerParser
            .parse(&full, &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"));
        for package in &mut parsed.packages {
            package.source_file = relative.clone();
        }
        parsed
    }

    #[test]
    fn composer_snapshot_strips_v_and_marks_dev() {
        let parsed = parse_fixture("composer");
        let schema = parsed
            .packages
            .iter()
            .find(|package| package.name == "justinrainbow/json-schema")
            .expect("json-schema");
        assert_eq!(schema.version, "5.2.13");
        assert_eq!(schema.direct, Some(true));
        assert!(!schema.dev);
        let bridge = parsed
            .packages
            .iter()
            .find(|package| package.name == "symfony/phpunit-bridge")
            .expect("phpunit-bridge");
        assert_eq!(bridge.version, "7.0.3");
        assert!(bridge.dev);
        assert_eq!(bridge.direct, Some(true));
        insta::assert_yaml_snapshot!("composer_tool", parsed);
    }

    #[test]
    fn phpunit_snapshot_marks_transitive_parser() {
        let parsed = parse_fixture("phpunit");
        let parser = parsed
            .packages
            .iter()
            .find(|package| package.name == "nikic/php-parser")
            .expect("php-parser");
        assert_eq!(parser.version, "4.17.1");
        assert_eq!(parser.direct, Some(false));
        let copy = parsed
            .packages
            .iter()
            .find(|package| package.name == "myclabs/deep-copy")
            .expect("deep-copy");
        assert_eq!(copy.direct, Some(true));
        insta::assert_yaml_snapshot!("phpunit", parsed);
    }

    #[test]
    fn php2shell_demo_pins_vulnerable_php() {
        let relative = "examples/php2shell-demo/composer.lock";
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        let content = fs::read_to_string(&full).expect("demo lock");
        let parsed = ComposerParser.parse(&full, &content).expect("demo");
        let php = parsed
            .packages
            .iter()
            .find(|package| package.name == "php")
            .expect("php platform package");
        assert_eq!(php.version, "8.3.35");
        assert_eq!(php.ecosystem, Ecosystem::Packagist);
        assert_eq!(php.direct, Some(true));
    }

    #[test]
    fn branch_and_path_versions_are_skipped() {
        let lock = r#"{
            "packages": [
                {"name": "symfony/yaml", "version": "dev-main"},
                {"name": "symfony/http-foundation", "version": "8.1.x-dev"},
                {"name": "acme/local-pkg", "version": "dev-main", "dist": {"type": "path"}},
                {"name": "acme/path-release", "version": "1.2.3", "dist": {"type": "path"}},
                {"name": "symfony/console", "version": "v6.4.1"}
            ]
        }"#;
        let parsed = ComposerParser
            .parse(Path::new("composer.lock"), lock)
            .expect("parse");
        let names: Vec<&str> = parsed
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, vec!["symfony/console"]);
        assert_eq!(parsed.packages[0].version, "6.4.1");
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("symfony/yaml@dev-main")));
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("symfony/http-foundation@8.1.x-dev")));
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("acme/path-release@1.2.3")));
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("acme/local-pkg@dev-main")));
    }

    #[test]
    fn broken_lockfile_names_the_file() {
        let err = ComposerParser
            .parse(Path::new("composer.lock"), "{")
            .expect_err("broken");
        let message = err.to_string();
        assert!(message.contains("composer.lock"), "{message}");
    }
}
