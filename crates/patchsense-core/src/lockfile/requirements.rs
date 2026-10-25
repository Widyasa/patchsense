//! Parser for pinned `requirements.txt` lines.
//!
//! Only `name==version` is kept. Extras (`name[extra]`) and environment
//! markers (`; ...`) are ignored. Comments, `-r`, `-e`, and other `-` options
//! are skipped. URLs are skipped. Any other non-empty line is reported as an
//! unpinned requirement with its 1-based line number.

use std::path::Path;

use crate::error::CoreError;
use crate::lockfile::{normalize_pypi_name, LockfileParser};
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `requirements.txt`.
pub struct RequirementsParser;

impl LockfileParser for RequirementsParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("requirements.txt"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_requirements(path, content)
    }
}

fn parse_requirements(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let source = display_path(path);
    let mut packages = Vec::new();
    let mut warnings = Vec::new();

    for (index, raw) in content.lines().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('-') || line.contains("://") || line.starts_with("git+") {
            continue;
        }
        match split_pin(line) {
            Some((name, version)) => packages.push(Package {
                ecosystem: Ecosystem::Pypi,
                name: normalize_pypi_name(name),
                version: version.to_string(),
                direct: Some(true),
                dev: false,
                source_file: source.clone(),
                line: Some(u32::try_from(line_no).unwrap_or(u32::MAX)),
            }),
            None => warnings.push(format!("{source}:{line_no}: baris tidak dipin, dilewati")),
        }
    }

    packages.sort_by(|left, right| {
        (&left.name, &left.version, left.line).cmp(&(&right.name, &right.version, right.line))
    });
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Pypi,
        packages,
        warnings,
    })
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(index) => &line[..index],
        None => line,
    }
}

fn split_pin(line: &str) -> Option<(&str, &str)> {
    let without_marker = line.split(';').next().unwrap_or(line).trim();
    let (name, version) = without_marker.split_once("==")?;
    let name = name.split('[').next().unwrap_or(name).trim();
    let version = version.trim();
    if name.is_empty() || version.is_empty() || version.contains(' ') {
        return None;
    }
    Some((name, version))
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
        RequirementsParser
            .parse(&path, &content)
            .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
    }

    #[test]
    fn jinja_snapshot() {
        let parsed = parse_repo_file("tests/fixtures/pypi/jinja/requirements.txt");
        assert!(
            parsed
                .packages
                .iter()
                .all(|package| package.direct == Some(true)),
            "requirements pins are direct"
        );
        insta::assert_yaml_snapshot!("jinja_packages", parsed.packages);
        insta::assert_yaml_snapshot!("jinja_warnings", parsed.warnings);
    }

    #[test]
    fn httpx_snapshot() {
        let parsed = parse_repo_file("tests/fixtures/pypi/httpx/requirements.txt");
        insta::assert_yaml_snapshot!("httpx_packages", parsed.packages);
        insta::assert_yaml_snapshot!("httpx_warnings", parsed.warnings);
        assert!(
            parsed
                .packages
                .iter()
                .any(|package| package.name == "coverage" && package.version == "7.6.0"),
            "extras should be stripped"
        );
    }

    #[test]
    fn skips_comments_options_urls_and_warns_on_unpinned_lines() {
        let content = "\
# comment
-r other.txt
-e git+https://example.com/pkg.git
requests>=2.0
Some_Package[security]==1.2.3 ; python_version >= \"3.8\"
https://example.com/foo.whl
Friendly.Bard==0.1.0
";
        let parsed = RequirementsParser
            .parse(Path::new("requirements.txt"), content)
            .expect("parse");
        let pairs: Vec<(&str, &str, Option<u32>)> = parsed
            .packages
            .iter()
            .map(|package| {
                (
                    package.name.as_str(),
                    package.version.as_str(),
                    package.line,
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("friendly-bard", "0.1.0", Some(7)),
                ("some-package", "1.2.3", Some(5)),
            ]
        );
        assert_eq!(
            parsed.warnings,
            vec!["requirements.txt:4: baris tidak dipin, dilewati".to_string()]
        );
    }
}
