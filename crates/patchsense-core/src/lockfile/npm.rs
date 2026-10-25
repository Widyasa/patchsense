//! Parser for npm `package-lock.json`.
//!
//! lockfileVersion 2 and 3 are read from `packages`. lockfileVersion 1 is read
//! from the nested `dependencies` tree (best effort). `link: true` entries are
//! skipped. `direct` is `Some(true)` only for a top-level `node_modules/<name>`
//! package whose name is listed in the root `dependencies` or `devDependencies`.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `package-lock.json`.
pub struct NpmPackageLockParser;

impl LockfileParser for NpmPackageLockParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("package-lock.json"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_package_lock(path, content)
    }
}

fn parse_package_lock(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let value: Value = serde_json::from_str(content)
        .map_err(|err| CoreError::parse(path, Some(err.line()), err.to_string()))?;
    let Some(root) = value.as_object() else {
        return Err(CoreError::parse(
            path,
            None,
            "package-lock.json is not a JSON object",
        ));
    };

    let version = root
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let source = display_path(path);
    let mut warnings = Vec::new();
    let mut packages = if version >= 2 || (version == 0 && root.contains_key("packages")) {
        parse_packages_map(path, root, &source, &mut warnings)?
    } else if root.contains_key("dependencies") {
        parse_v1_dependencies(root, &source, &mut warnings)
    } else {
        return Err(CoreError::parse(
            path,
            None,
            "package-lock.json has neither `packages` nor `dependencies`",
        ));
    };

    packages.sort_by(|left, right| {
        (&left.name, &left.version, left.dev, left.direct).cmp(&(
            &right.name,
            &right.version,
            right.dev,
            right.direct,
        ))
    });
    warnings.sort();
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Npm,
        packages,
        warnings,
    })
}

fn parse_packages_map(
    path: &Path,
    root: &Map<String, Value>,
    source: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<Package>, CoreError> {
    let Some(packages) = root.get("packages").and_then(Value::as_object) else {
        return Err(CoreError::parse(
            path,
            None,
            "package-lock.json v2/v3 is missing `packages`",
        ));
    };
    let direct_names = root_direct_names(packages.get("").and_then(Value::as_object));
    let mut parsed = Vec::new();
    for (key, value) in packages {
        if key.is_empty() {
            continue;
        }
        let Some(name) = name_from_packages_key(key) else {
            continue;
        };
        let Some(meta) = value.as_object() else {
            warnings.push(format!("{source}: entry `{key}` is not an object, skipped"));
            continue;
        };
        if meta.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(version) = meta.get("version").and_then(Value::as_str) else {
            warnings.push(format!("{source}: `{key}` has no version, skipped"));
            continue;
        };
        if !usable_npm_version(version) {
            warnings.push(format!(
                "{source}: `{key}` version `{version}` is not a registry version, skipped"
            ));
            continue;
        }
        let dev = meta.get("dev").and_then(Value::as_bool).unwrap_or(false);
        let top_level = key.matches("node_modules/").count() == 1;
        let direct = Some(top_level && direct_names.contains(&name));
        parsed.push(Package {
            ecosystem: Ecosystem::Npm,
            name,
            version: version.to_string(),
            direct,
            dev,
            source_file: source.to_string(),
            source_files: Vec::new(),
            line: None,
        });
    }
    Ok(parsed)
}

fn root_direct_names(root_package: Option<&Map<String, Value>>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(root_package) = root_package else {
        return names;
    };
    for field in ["dependencies", "devDependencies"] {
        if let Some(map) = root_package.get(field).and_then(Value::as_object) {
            names.extend(map.keys().cloned());
        }
    }
    names
}

fn name_from_packages_key(key: &str) -> Option<String> {
    let marker = "node_modules/";
    let index = key.rfind(marker)?;
    let name = &key[index + marker.len()..];
    if name.is_empty() || name.ends_with('/') {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_v1_dependencies(
    root: &Map<String, Value>,
    source: &str,
    warnings: &mut Vec<String>,
) -> Vec<Package> {
    let mut parsed = Vec::new();
    if let Some(deps) = root.get("dependencies").and_then(Value::as_object) {
        walk_v1(deps, true, source, &mut parsed, warnings);
    }
    parsed
}

fn walk_v1(
    deps: &Map<String, Value>,
    direct: bool,
    source: &str,
    parsed: &mut Vec<Package>,
    warnings: &mut Vec<String>,
) {
    for (name, value) in deps {
        let Some(meta) = value.as_object() else {
            warnings.push(format!(
                "{source}: dependency `{name}` is not an object, skipped"
            ));
            continue;
        };
        if meta.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        match meta.get("version").and_then(Value::as_str) {
            Some(version) if usable_npm_version(version) => {
                let dev = meta.get("dev").and_then(Value::as_bool).unwrap_or(false);
                parsed.push(Package {
                    ecosystem: Ecosystem::Npm,
                    name: name.clone(),
                    version: version.to_string(),
                    direct: Some(direct),
                    dev,
                    source_file: source.to_string(),
                    source_files: Vec::new(),
                    line: None,
                });
            }
            Some(version) => warnings.push(format!(
                "{source}: `{name}` version `{version}` is not a registry version, skipped"
            )),
            None => warnings.push(format!("{source}: `{name}` has no version, skipped")),
        }
        if let Some(nested) = meta.get("dependencies").and_then(Value::as_object) {
            walk_v1(nested, false, source, parsed, warnings);
        }
    }
}

fn usable_npm_version(version: &str) -> bool {
    let version = version.trim();
    !version.is_empty()
        && !version.contains("://")
        && !version.starts_with("file:")
        && !version.starts_with("git+")
        && !version.starts_with("git:")
        && !version.starts_with("github:")
        && !version.starts_with("http:")
        && !version.starts_with("https:")
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

    fn parse_repo_file(relative: &str) -> ParsedLockfile {
        let path = PathBuf::from(relative);
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&path);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        NpmPackageLockParser
            .parse(&path, &content)
            .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
    }

    #[test]
    fn preact_v3_snapshot() {
        let parsed = parse_repo_file("tests/fixtures/npm/preact/package-lock.json");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        insta::assert_yaml_snapshot!(parsed.packages);
    }

    #[test]
    fn lodash_v1_snapshot() {
        let parsed = parse_repo_file("tests/fixtures/npm/lodash/package-lock.json");
        insta::assert_yaml_snapshot!(parsed.packages);
        assert!(
            parsed
                .packages
                .iter()
                .any(|package| package.name == "lodash" && package.version == "4.17.14"),
            "trimmed lodash v1 fixture should keep the nested lodash 4.17.14 entry"
        );
    }

    #[test]
    fn broken_lockfile_names_the_file() {
        let path = Path::new("app/package-lock.json");
        let err = NpmPackageLockParser
            .parse(path, "{")
            .expect_err("broken json");
        let message = err.to_string();
        assert!(message.contains("app/package-lock.json"), "{message}");
        assert!(
            message.contains(":1") || message.contains(":2"),
            "{message}"
        );
    }

    #[test]
    fn link_entries_are_skipped_and_scoped_nested_names_work() {
        let content = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {
              "dependencies": { "@scope/pkg": "1.0.0" },
              "devDependencies": { "lodash": "4.17.15" }
            },
            "node_modules/@scope/pkg": { "version": "1.2.3" },
            "node_modules/@scope/pkg/node_modules/inner": { "version": "0.1.0" },
            "node_modules/lodash": { "version": "4.17.15", "dev": true },
            "node_modules/linked": { "version": "1.0.0", "link": true },
            "node_modules/filedep": { "version": "file:../filedep" }
          }
        }"#;
        let parsed = NpmPackageLockParser
            .parse(Path::new("package-lock.json"), content)
            .expect("parse");
        let names: Vec<&str> = parsed
            .packages
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, vec!["@scope/pkg", "inner", "lodash"]);
        let scoped = parsed
            .packages
            .iter()
            .find(|package| package.name == "@scope/pkg")
            .unwrap();
        assert_eq!(scoped.direct, Some(true));
        assert!(!scoped.dev);
        let inner = parsed
            .packages
            .iter()
            .find(|package| package.name == "inner")
            .unwrap();
        assert_eq!(inner.direct, Some(false));
        let lodash = parsed
            .packages
            .iter()
            .find(|package| package.name == "lodash")
            .unwrap();
        assert_eq!(lodash.direct, Some(true));
        assert!(lodash.dev);
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("filedep")));
    }
}
