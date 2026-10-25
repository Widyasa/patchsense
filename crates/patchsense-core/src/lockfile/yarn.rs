//! Parser for classic Yarn v1 `yarn.lock`.
//!
//! A block header lists one or more specs (`"name@range", other@range:`) and
//! the resolved version is the indented `version "..."` line. Scoped names
//! keep the leading `@`. Berry lockfiles start with `__metadata` and are
//! rejected here so they are not read as classic.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `yarn.lock`.
pub struct YarnParser;

impl LockfileParser for YarnParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("yarn.lock"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_yarn_classic(path, content)
    }
}

fn parse_yarn_classic(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    if is_berry(content) {
        return Err(CoreError::parse(
            path,
            None,
            "yarn berry lockfiles are not parsed by the classic parser",
        ));
    }
    let mut pending: Vec<String> = Vec::new();
    let mut found: BTreeMap<(String, String), ()> = BTreeMap::new();
    for (index, line) in content.lines().enumerate() {
        let line_no = index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            pending.clear();
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if !line.trim_end().ends_with(':') {
                return Err(CoreError::parse(
                    path,
                    Some(line_no),
                    format!("expected a yarn spec header, got {line}"),
                ));
            }
            pending = header_names(line);
            if pending.is_empty() {
                return Err(CoreError::parse(
                    path,
                    Some(line_no),
                    "yarn spec header has no package name",
                ));
            }
            continue;
        }
        if let Some(version) = version_field(line) {
            for name in &pending {
                found.insert((name.clone(), version.clone()), ());
            }
        }
    }

    let sibling = package_json_deps(path)?;
    let source = display_path(path);
    let mut packages: Vec<Package> = found
        .into_keys()
        .map(|(name, version)| {
            let (direct, dev) = match &sibling {
                None => (None, false),
                Some(info) => {
                    let is_dep = info.dependencies.contains(&name);
                    let is_dev = info.dev_dependencies.contains(&name);
                    (Some(is_dep || is_dev), is_dev && !is_dep)
                }
            };
            Package {
                ecosystem: Ecosystem::Npm,
                name,
                version,
                direct,
                dev,
                source_file: source.clone(),
                line: None,
            }
        })
        .collect();
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Npm,
        packages,
        warnings: Vec::new(),
    })
}

fn is_berry(content: &str) -> bool {
    content
        .lines()
        .any(|line| line.trim_start().starts_with("__metadata:"))
}

fn header_names(line: &str) -> Vec<String> {
    let line = line.trim().trim_end_matches(':');
    let mut names = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch == ',' && !quoted {
            if let Some(name) = spec_name(current.trim()) {
                names.push(name);
            }
            current.clear();
            continue;
        }
        current.push(ch);
    }
    if let Some(name) = spec_name(current.trim()) {
        names.push(name);
    }
    names
}

fn spec_name(spec: &str) -> Option<String> {
    let spec = spec.trim().trim_matches('"');
    if spec.is_empty() {
        return None;
    }
    if let Some(rest) = spec.strip_prefix('@') {
        let (name, _) = rest.split_once('@')?;
        if name.is_empty() {
            return None;
        }
        return Some(format!("@{name}"));
    }
    let (name, _) = spec.split_once('@')?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn version_field(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix("version ")?;
    let version = rest.trim().trim_matches('"').trim_matches('\'');
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

struct PackageJsonDeps {
    dependencies: BTreeSet<String>,
    dev_dependencies: BTreeSet<String>,
}

fn package_json_deps(lock_path: &Path) -> Result<Option<PackageJsonDeps>, CoreError> {
    let Some(parent) = lock_path.parent() else {
        return Ok(None);
    };
    let sibling = parent.join("package.json");
    if !sibling.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&sibling).map_err(|source| CoreError::Io {
        path: sibling.clone(),
        source,
    })?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| CoreError::parse(sibling.clone(), Some(err.line()), err.to_string()))?;
    let mut dependencies = BTreeSet::new();
    let mut dev_dependencies = BTreeSet::new();
    collect_names(&value, "dependencies", &mut dependencies);
    collect_names(&value, "optionalDependencies", &mut dependencies);
    collect_names(&value, "devDependencies", &mut dev_dependencies);
    Ok(Some(PackageJsonDeps {
        dependencies,
        dev_dependencies,
    }))
}

fn collect_names(value: &Value, key: &str, into: &mut BTreeSet<String>) {
    let Some(table) = value.get(key).and_then(Value::as_object) else {
        return;
    };
    for name in table.keys() {
        into.insert(name.clone());
    }
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
        let relative = format!("tests/fixtures/yarn/{project}/yarn.lock");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        let mut parsed = YarnParser
            .parse(&full, &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"));
        for package in &mut parsed.packages {
            package.source_file = relative.clone();
        }
        parsed
    }

    #[test]
    fn lodash_snapshot_marks_dev_dependencies() {
        let parsed = parse_fixture("lodash");
        let chalk = parsed
            .packages
            .iter()
            .find(|package| package.name == "chalk")
            .expect("chalk");
        assert_eq!(chalk.version, "1.1.3");
        assert_eq!(chalk.direct, Some(true));
        assert!(chalk.dev);
        let styles = parsed
            .packages
            .iter()
            .find(|package| package.name == "ansi-styles")
            .expect("ansi-styles");
        assert_eq!(styles.direct, Some(false));
        assert!(!styles.dev);
        insta::assert_yaml_snapshot!("lodash_classic", parsed);
    }

    #[test]
    fn prettier_snapshot_keeps_scoped_names() {
        let parsed = parse_fixture("prettier");
        let frame = parsed
            .packages
            .iter()
            .find(|package| package.name == "@babel/code-frame")
            .expect("code-frame");
        assert_eq!(frame.version, "7.0.0");
        assert_eq!(frame.direct, Some(true));
        assert!(!frame.dev);
        let highlight = parsed
            .packages
            .iter()
            .find(|package| package.name == "@babel/highlight")
            .expect("highlight");
        assert_eq!(highlight.version, "7.16.10");
        assert_eq!(highlight.direct, Some(false));
        insta::assert_yaml_snapshot!("prettier_classic", parsed);
    }

    #[test]
    fn missing_package_json_leaves_direct_unknown() {
        let content = "left-pad@^1.0.0:\n  version \"1.3.0\"\n";
        let parsed = YarnParser
            .parse(Path::new("missing/yarn.lock"), content)
            .expect("parse");
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].direct, None);
        assert!(!parsed.packages[0].dev);
    }

    #[test]
    fn berry_metadata_is_not_classic() {
        let err = YarnParser
            .parse(Path::new("yarn.lock"), "__metadata:\n  version: 6\n")
            .expect_err("berry");
        let message = err.to_string();
        assert!(message.contains("berry"), "{message}");
        assert!(message.contains("yarn.lock"), "{message}");
    }
}
