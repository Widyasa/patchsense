//! Parser for `pnpm-lock.yaml` v6 and v9.
//!
//! v6 package keys look like `/name@version` or `/name/version`. v9 keys live
//! in `packages` and `snapshots` and look like `name@version`. A peer suffix
//! `(...)` is ignored, so the same package is recorded once. `direct` comes
//! from every importer's `dependencies`, `devDependencies`, and
//! `optionalDependencies`. `dev` is true when that importer entry is a dev
//! dependency, or when a v6 package object sets `dev: true`.

use std::collections::BTreeMap;
use std::path::Path;

use serde_yaml::Value;

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `pnpm-lock.yaml`.
pub struct PnpmParser;

impl LockfileParser for PnpmParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("pnpm-lock.yaml"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_pnpm(path, content)
    }
}

fn parse_pnpm(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let doc: Value = serde_yaml::from_str(content).map_err(|err| {
        let line = err.location().map(|location| location.line());
        CoreError::parse(path, line, err.to_string())
    })?;
    if !doc.is_mapping() {
        return Err(CoreError::parse(
            path,
            None,
            "pnpm-lock.yaml is not a YAML mapping",
        ));
    }

    let direct = direct_versions(&doc);
    let mut found: BTreeMap<(String, String), (Option<bool>, bool)> = BTreeMap::new();
    let mut saw_catalog = false;
    for section in ["packages", "snapshots"] {
        let Some(entries) = doc.get(section).and_then(Value::as_mapping) else {
            continue;
        };
        saw_catalog = true;
        for (key, entry) in entries {
            let Some(key) = key.as_str() else {
                continue;
            };
            let Some((name, version)) = parse_package_key(key) else {
                continue;
            };
            let entry_dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false);
            let (is_direct, dev) = match direct.get(&(name.clone(), version.clone())) {
                Some(dev_only) => (Some(true), *dev_only),
                None => (Some(false), entry_dev),
            };
            found
                .entry((name, version))
                .and_modify(|(existing_direct, existing_dev)| {
                    *existing_direct = merge_direct(*existing_direct, is_direct);
                    *existing_dev = *existing_dev && dev;
                })
                .or_insert((is_direct, dev));
        }
    }
    if !saw_catalog {
        return Err(CoreError::parse(
            path,
            None,
            "pnpm-lock.yaml is missing packages",
        ));
    }

    let source = display_path(path);
    let mut packages: Vec<Package> = found
        .into_iter()
        .map(|((name, version), (direct, dev))| Package {
            ecosystem: Ecosystem::Npm,
            name,
            version,
            direct,
            dev,
            source_file: source.clone(),
            line: None,
        })
        .collect();
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Npm,
        packages,
        warnings: Vec::new(),
    })
}

/// `true` means the importer lists this name@version only as a dev dependency.
fn direct_versions(doc: &Value) -> BTreeMap<(String, String), bool> {
    let mut found = BTreeMap::new();
    let Some(importers) = doc.get("importers").and_then(Value::as_mapping) else {
        return found;
    };
    for body in importers.values() {
        for (section, dev_section) in [
            ("dependencies", false),
            ("devDependencies", true),
            ("optionalDependencies", false),
        ] {
            let Some(deps) = body.get(section).and_then(Value::as_mapping) else {
                continue;
            };
            for (name, spec) in deps {
                let Some(name) = name.as_str() else {
                    continue;
                };
                let Some(version) = spec.get("version").and_then(Value::as_str) else {
                    continue;
                };
                let version = strip_peer(version);
                if skip_version(version) {
                    continue;
                }
                found
                    .entry((name.to_string(), version.to_string()))
                    .and_modify(|dev| *dev = *dev && dev_section)
                    .or_insert(dev_section);
            }
        }
    }
    found
}

fn merge_direct(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        (None, None) => None,
    }
}

fn strip_peer(value: &str) -> &str {
    value
        .split_once('(')
        .map(|(base, _)| base)
        .unwrap_or(value)
        .trim()
}

fn skip_version(version: &str) -> bool {
    version.is_empty()
        || version.starts_with("link:")
        || version.starts_with("file:")
        || version.starts_with("workspace:")
}

/// Split a pnpm package key into name and version.
///
/// Accepts `/name@version`, `/name/version`, `name@version`, and the scoped
/// forms of each. A `(peer)` suffix is ignored.
pub(crate) fn parse_package_key(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    if raw.starts_with("file:") || raw.starts_with("link:") || raw.starts_with("workspace:") {
        return None;
    }
    let without_peer = strip_peer(raw).trim_end_matches('/');
    let body = without_peer.strip_prefix('/').unwrap_or(without_peer);
    if body.is_empty() {
        return None;
    }
    if let Some(rest) = body.strip_prefix('@') {
        if let Some((name, version)) = rest.rsplit_once('@') {
            if !name.is_empty() && valid_version(version) {
                return Some((format!("@{name}"), version.to_string()));
            }
        }
        let mut parts = rest.split('/');
        let scope = parts.next()?;
        let name = parts.next()?;
        let version = parts.next()?;
        if parts.next().is_some() || scope.is_empty() || name.is_empty() || !valid_version(version)
        {
            return None;
        }
        return Some((format!("@{scope}/{name}"), version.to_string()));
    }
    if let Some((name, version)) = body.rsplit_once('@') {
        if !name.is_empty() && !name.contains('/') && valid_version(version) {
            return Some((name.to_string(), version.to_string()));
        }
    }
    let (name, version) = body.split_once('/')?;
    if name.is_empty() || name.contains('/') || !valid_version(version) {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn valid_version(version: &str) -> bool {
    !version.is_empty() && !version.contains('/') && !version.contains('@')
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
    use std::fs;
    use std::path::PathBuf;

    fn parse_fixture(project: &str) -> ParsedLockfile {
        let relative = format!("tests/fixtures/pnpm/{project}/pnpm-lock.yaml");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        let mut parsed = PnpmParser
            .parse(&full, &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"));
        for package in &mut parsed.packages {
            package.source_file = relative.clone();
        }
        parsed
    }

    #[test]
    fn vite5_v6_snapshot() {
        let parsed = parse_fixture("vite5");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let babel = parsed
            .packages
            .iter()
            .find(|package| package.name == "@babel/types")
            .expect("@babel/types");
        assert_eq!(babel.version, "7.23.3");
        assert_eq!(babel.direct, Some(true));
        assert!(babel.dev);
        let transitive = parsed
            .packages
            .iter()
            .find(|package| package.name == "to-fast-properties")
            .expect("to-fast-properties");
        assert_eq!(transitive.direct, Some(false));
        assert!(!transitive.dev);
        let rollup = parsed
            .packages
            .iter()
            .find(|package| package.name == "@rollup/plugin-typescript")
            .expect("plugin-typescript");
        assert_eq!(rollup.version, "11.1.5");
        assert_eq!(
            parsed
                .packages
                .iter()
                .filter(|package| package.name == "@rollup/plugin-typescript")
                .count(),
            1,
            "peer suffix must not duplicate the package"
        );
        insta::assert_yaml_snapshot!("vite5_v6", parsed);
    }

    #[test]
    fn vite6_v9_snapshot() {
        let parsed = parse_fixture("vite6");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let eslint = parsed
            .packages
            .iter()
            .find(|package| package.name == "@eslint/js")
            .expect("@eslint/js");
        assert_eq!(eslint.version, "9.15.0");
        assert_eq!(eslint.direct, Some(true));
        assert!(eslint.dev);
        let cli = parsed
            .packages
            .iter()
            .find(|package| package.name == "conventional-changelog-cli")
            .expect("conventional-changelog-cli");
        assert_eq!(cli.version, "5.0.0");
        assert_eq!(
            parsed
                .packages
                .iter()
                .filter(|package| package.name == "conventional-changelog-cli")
                .count(),
            1
        );
        let transitive = parsed
            .packages
            .iter()
            .find(|package| package.name == "add-stream")
            .expect("add-stream");
        assert_eq!(transitive.direct, Some(false));
        insta::assert_yaml_snapshot!("vite6_v9", parsed);
    }

    #[test]
    fn slash_form_and_scoped_slash_form_parse() {
        let content = r#"
lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
packages:
  /left-pad/1.3.0:
    resolution:
      integrity: sha512-demo
  /@scope/left-pad/1.3.0:
    resolution:
      integrity: sha512-demo
"#;
        let parsed = PnpmParser
            .parse(Path::new("synthetic_pnpm_slash.yaml"), content)
            .expect("slash form");
        let names: Vec<_> = parsed
            .packages
            .iter()
            .map(|package| {
                (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.direct,
                )
            })
            .collect();
        assert_eq!(
            names,
            vec![
                ("@scope/left-pad", "1.3.0", Some(false)),
                ("left-pad", "1.3.0", Some(true)),
            ]
        );
    }

    #[test]
    fn broken_lockfile_names_the_file() {
        let path = Path::new("pnpm-lock.yaml");
        let err = PnpmParser
            .parse(path, "lockfileVersion: [\n")
            .expect_err("broken yaml");
        let message = err.to_string();
        assert!(message.contains("pnpm-lock.yaml"), "{message}");
    }
}
