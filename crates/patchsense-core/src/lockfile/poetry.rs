//! Parser for Poetry `poetry.lock`.
//!
//! Each `[[package]]` becomes a package. `category` / `groups` mark dev
//! dependencies when the lockfile still carries them. `direct` comes from a
//! sibling `pyproject.toml` when one exists: `[tool.poetry.dependencies]` and
//! `[project].dependencies`. Without that file, `direct` is `None`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::CoreError;
use crate::lockfile::{normalize_pypi_name, LockfileParser};
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `poetry.lock`.
pub struct PoetryParser;

impl LockfileParser for PoetryParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("poetry.lock"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_poetry(path, content)
    }
}

#[derive(Debug, Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Debug, Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PyProject {
    #[serde(default)]
    tool: Option<Tool>,
    #[serde(default)]
    project: Option<ProjectTable>,
}

#[derive(Debug, Deserialize)]
struct Tool {
    #[serde(default)]
    poetry: Option<PoetryTool>,
}

#[derive(Debug, Deserialize)]
struct PoetryTool {
    #[serde(default)]
    dependencies: Option<toml::Table>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: Option<toml::Table>,
    #[serde(default)]
    group: Option<toml::Table>,
}

#[derive(Debug, Deserialize)]
struct ProjectTable {
    #[serde(default)]
    dependencies: Option<Vec<String>>,
}

struct PyProjectInfo {
    direct: BTreeSet<String>,
    dev: BTreeSet<String>,
}

fn parse_poetry(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let lock: PoetryLock = toml::from_str(content)
        .map_err(|err| CoreError::parse(path, None, format!("invalid poetry.lock: {err}")))?;
    let source = display_path(path);
    let mut warnings = Vec::new();
    let pyproject = read_pyproject(path, &source, &mut warnings);

    let mut packages = Vec::new();
    for package in lock.package {
        if package.name.is_empty() || package.version.is_empty() {
            warnings.push(format!(
                "{source}: package entry missing name or version, skipped"
            ));
            continue;
        }
        let name = normalize_pypi_name(&package.name);
        let lock_dev = is_lock_dev(package.category.as_deref(), package.groups.as_ref());
        let (direct, dev) = match &pyproject {
            Some(info) => {
                let direct = info.direct.contains(&name);
                let dev = lock_dev || (info.dev.contains(&name) && !direct);
                (Some(direct), dev)
            }
            None => (None, lock_dev),
        };
        packages.push(Package {
            ecosystem: Ecosystem::Pypi,
            name,
            version: package.version,
            direct,
            dev,
            source_file: source.clone(),
            line: None,
        });
    }
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Pypi,
        packages,
        warnings,
    })
}

fn is_lock_dev(category: Option<&str>, groups: Option<&Vec<String>>) -> bool {
    if category == Some("dev") {
        return true;
    }
    if let Some(groups) = groups {
        return !groups.is_empty() && !groups.iter().any(|group| group == "main");
    }
    false
}

fn read_pyproject(
    lock_path: &Path,
    source: &str,
    warnings: &mut Vec<String>,
) -> Option<PyProjectInfo> {
    let parent = lock_path.parent()?;
    let pyproject_path = parent.join("pyproject.toml");
    if !pyproject_path.is_file() {
        return None;
    }
    let text = match fs::read_to_string(&pyproject_path) {
        Ok(text) => text,
        Err(err) => {
            warnings.push(format!(
                "{source}: could not read {}: {err}",
                display_path(&pyproject_path)
            ));
            return None;
        }
    };
    match pyproject_info(&text) {
        Ok(info) => Some(info),
        Err(err) => {
            warnings.push(format!(
                "{source}: could not parse {}: {err}",
                display_path(&pyproject_path)
            ));
            None
        }
    }
}

fn pyproject_info(text: &str) -> Result<PyProjectInfo, String> {
    let doc: PyProject = toml::from_str(text).map_err(|err| err.to_string())?;
    let mut direct = BTreeSet::new();
    let mut dev = BTreeSet::new();
    if let Some(poetry) = doc.tool.as_ref().and_then(|tool| tool.poetry.as_ref()) {
        if let Some(deps) = &poetry.dependencies {
            for name in deps.keys() {
                if name != "python" {
                    direct.insert(normalize_pypi_name(name));
                }
            }
        }
        if let Some(deps) = &poetry.dev_dependencies {
            for name in deps.keys() {
                if name != "python" {
                    dev.insert(normalize_pypi_name(name));
                }
            }
        }
        if let Some(groups) = &poetry.group {
            for (group_name, group_value) in groups {
                if group_name == "main" {
                    continue;
                }
                let Some(table) = group_value.as_table() else {
                    continue;
                };
                let Some(deps) = table.get("dependencies").and_then(toml::Value::as_table) else {
                    continue;
                };
                for name in deps.keys() {
                    dev.insert(normalize_pypi_name(name));
                }
            }
        }
    }
    if let Some(dependencies) = doc
        .project
        .as_ref()
        .and_then(|project| project.dependencies.as_ref())
    {
        for spec in dependencies {
            if let Some(name) = requirement_name(spec) {
                direct.insert(normalize_pypi_name(name));
            }
        }
    }
    Ok(PyProjectInfo { direct, dev })
}

fn requirement_name(spec: &str) -> Option<&str> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let end = spec
        .find([' ', '<', '>', '=', '!', '~', '[', ';', '@'])
        .unwrap_or(spec.len());
    let name = spec[..end].trim();
    if name.is_empty() {
        None
    } else {
        Some(name)
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
        let relative = format!("tests/fixtures/pypi/{project}/poetry.lock");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        let mut parsed = PoetryParser
            .parse(&full, &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"));
        for package in &mut parsed.packages {
            package.source_file = relative.clone();
        }
        for warning in &mut parsed.warnings {
            *warning = warning.replace(&display_path(&full), &relative);
        }
        parsed
    }

    #[test]
    fn rich_snapshot_uses_pyproject() {
        let parsed = parse_fixture("rich");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let pygments = parsed
            .packages
            .iter()
            .find(|package| package.name == "pygments")
            .expect("pygments");
        assert_eq!(pygments.direct, Some(true));
        assert!(!pygments.dev);
        let pytest = parsed
            .packages
            .iter()
            .find(|package| package.name == "pytest")
            .expect("pytest");
        assert_eq!(pytest.direct, Some(false));
        assert!(pytest.dev);
        let mdurl = parsed
            .packages
            .iter()
            .find(|package| package.name == "mdurl")
            .expect("mdurl");
        assert_eq!(mdurl.direct, Some(false));
        assert!(!mdurl.dev);
        insta::assert_yaml_snapshot!("rich_packages", parsed.packages);
    }

    #[test]
    fn poetry_project_snapshot_uses_pyproject() {
        let parsed = parse_fixture("poetry");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let requests = parsed
            .packages
            .iter()
            .find(|package| package.name == "requests")
            .expect("requests");
        assert_eq!(requests.direct, Some(true));
        let urllib3 = parsed
            .packages
            .iter()
            .find(|package| package.name == "urllib3")
            .expect("urllib3");
        assert_eq!(urllib3.direct, Some(false));
        insta::assert_yaml_snapshot!("poetry_packages", parsed.packages);
    }

    #[test]
    fn missing_pyproject_leaves_direct_unknown() {
        let content = r#"
[[package]]
name = "Requests"
version = "2.32.3"
category = "main"

[[package]]
name = "pytest"
version = "8.3.2"
groups = ["dev"]
"#;
        let parsed = PoetryParser
            .parse(Path::new("no-such-dir/poetry.lock"), content)
            .expect("parse");
        assert!(parsed
            .packages
            .iter()
            .all(|package| package.direct.is_none()));
        let pytest = parsed
            .packages
            .iter()
            .find(|package| package.name == "pytest")
            .unwrap();
        assert!(pytest.dev);
        let requests = parsed
            .packages
            .iter()
            .find(|package| package.name == "requests")
            .unwrap();
        assert!(!requests.dev);
    }
}
