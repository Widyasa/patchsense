//! Parser for pinned requirements files.
//!
//! Recognised names, compared case-insensitively:
//!
//! - `requirements.txt`
//! - `requirements-*.txt`, `requirements_*.txt`, and `requirements.*.txt`
//! - `*.requirements.txt`
//! - any `.txt` file in a directory named `requirements`
//!
//! Only `name==version` is kept. Extras (`name[extra]`) and environment
//! markers (`; ...`) are ignored. Comments, `-e`, and other `-` options are
//! skipped. URLs are skipped. Any other non-empty line is reported as an
//! unpinned requirement with its 1-based line number.
//!
//! `-r`, `--requirement`, `-c`, and `--constraint` are read from disk,
//! relative to the file that names them, and parsed the same way. A repeated
//! name and version is kept once. A cycle is a warning. A missing include is
//! a warning and does not fail the parse.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::CoreError;
use crate::lockfile::{normalize_pypi_name, LockfileParser};
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for requirements files.
pub struct RequirementsParser;

impl LockfileParser for RequirementsParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn matches(&self, path: &Path) -> bool {
        is_requirements_file(path)
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_requirements(path, content)
    }
}

const MAX_INCLUDE_DEPTH: usize = 64;

fn parse_requirements(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    let mut stack = Vec::new();
    walk_requirements(path, content, &mut stack, &mut packages, &mut warnings);
    let mut seen = HashSet::new();
    packages.retain(|package| seen.insert((package.name.clone(), package.version.clone())));
    packages.sort_by(|left, right| {
        (&left.name, &left.version, left.line).cmp(&(&right.name, &right.version, right.line))
    });
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Pypi,
        packages,
        warnings,
    })
}

fn walk_requirements(
    path: &Path,
    content: &str,
    stack: &mut Vec<PathBuf>,
    packages: &mut Vec<Package>,
    warnings: &mut Vec<String>,
) {
    let id = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if stack.iter().any(|seen| seen == &id) {
        warnings.push(format!("{}: include cycle, skipped", display_path(path)));
        return;
    }
    if stack.len() >= MAX_INCLUDE_DEPTH {
        warnings.push(format!(
            "{}: include depth exceeded, skipped",
            display_path(path)
        ));
        return;
    }
    stack.push(id);
    let source = display_path(path);
    for (index, raw) in content.lines().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(include) = include_target(line) {
            if include.contains("://") {
                warnings.push(format!(
                    "{source}:{line_no}: remote include {include} was skipped"
                ));
                continue;
            }
            let resolved = resolve_include(path, include);
            match fs::read_to_string(&resolved) {
                Ok(body) => {
                    walk_requirements(&resolved, &body, stack, packages, warnings);
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    warnings.push(format!(
                        "{source}:{line_no}: include {} was not found, skipped",
                        display_path(&resolved)
                    ));
                }
                Err(err) => {
                    warnings.push(format!(
                        "{source}:{line_no}: include {} could not be read ({err}), skipped",
                        display_path(&resolved)
                    ));
                }
            }
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
                source_files: Vec::new(),
                line: Some(u32::try_from(line_no).unwrap_or(u32::MAX)),
            }),
            None => warnings.push(format!("{source}:{line_no}: line is not pinned, skipped")),
        }
    }
    stack.pop();
}

fn include_target(line: &str) -> Option<&str> {
    for (long, short) in [("--requirement", "-r"), ("--constraint", "-c")] {
        if let Some(rest) = line.strip_prefix(long) {
            return option_path(rest, true);
        }
        if let Some(rest) = line.strip_prefix(short) {
            return option_path(rest, false);
        }
    }
    None
}

fn option_path(rest: &str, long: bool) -> Option<&str> {
    let rest = if long {
        if let Some(rest) = rest.strip_prefix('=') {
            rest
        } else if rest.starts_with(char::is_whitespace) {
            rest
        } else {
            return None;
        }
    } else if rest.is_empty() {
        return None;
    } else {
        rest
    };
    let token = rest.split_whitespace().next()?;
    let token = unquote(token);
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn unquote(token: &str) -> &str {
    let bytes = token.as_bytes();
    if token.len() >= 2 {
        let quote = bytes[0];
        if (quote == b'"' || quote == b'\'') && bytes[token.len() - 1] == quote {
            return &token[1..token.len() - 1];
        }
    }
    token
}

fn resolve_include(from: &Path, include: &str) -> PathBuf {
    let include = Path::new(include);
    if include.is_absolute() {
        return include.to_path_buf();
    }
    from.parent().unwrap_or(Path::new("")).join(include)
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

/// File names such as `requirements-dev.txt` and `app.requirements.txt`, plus
/// any `.txt` file whose parent directory is named `requirements`.
fn is_requirements_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if !lower.ends_with(".txt") {
        return false;
    }
    let stem = &lower[..lower.len() - 4];
    if stem == "requirements"
        || stem.starts_with("requirements-")
        || stem.starts_with("requirements_")
        || stem.starts_with("requirements.")
        || stem.ends_with(".requirements")
    {
        return true;
    }
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|dir| dir.to_str())
        .is_some_and(|dir| dir.eq_ignore_ascii_case("requirements"))
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
    use crate::lockfile::parser_for;
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
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("requirements.txt");
        fs::write(&path, content).expect("write");
        let parsed = RequirementsParser.parse(&path, content).expect("parse");
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
        assert_eq!(parsed.warnings.len(), 2, "{:?}", parsed.warnings);
        assert!(
            parsed.warnings[0].contains(":2: include ")
                && parsed.warnings[0].contains("other.txt")
                && parsed.warnings[0].ends_with("was not found, skipped"),
            "{:?}",
            parsed.warnings
        );
        assert!(
            parsed.warnings[1].ends_with(":4: line is not pinned, skipped"),
            "{:?}",
            parsed.warnings
        );
    }

    #[test]
    fn includes_are_resolved_deduped_and_cycles_warn() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/pypi/includes/requirements.txt");
        let content = fs::read_to_string(&root).expect("fixture");
        let parsed = RequirementsParser
            .parse(&root, &content)
            .expect("parse fixture");
        let pairs: Vec<(&str, &str)> = parsed
            .packages
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("flask", "3.0.3"),
                ("langchain", "0.2.16"),
                ("requests", "2.32.3"),
            ]
        );
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let requests = parsed
            .packages
            .iter()
            .find(|package| package.name == "requests")
            .expect("requests");
        assert!(
            requests.source_file.ends_with("includes/requirements.txt"),
            "{}",
            requests.source_file
        );
        let langchain = parsed
            .packages
            .iter()
            .find(|package| package.name == "langchain")
            .expect("langchain");
        assert!(langchain.source_file.ends_with("requirements-rag.txt"));

        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        fs::write(&a, "alpha==1.0.0\n-r b.txt\n").expect("a");
        fs::write(&b, "beta==2.0.0\n--requirement a.txt\n").expect("b");
        let a_body = fs::read_to_string(&a).expect("read a");
        let cycled = RequirementsParser.parse(&a, &a_body).expect("cycle");
        let names: Vec<&str> = cycled.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        assert!(
            cycled
                .warnings
                .iter()
                .any(|warning| warning.contains("include cycle")),
            "{:?}",
            cycled.warnings
        );

        let missing = dir.path().join("missing-parent.txt");
        let missing_body = "kept==1.2.3\n-c gone.txt\n--requirement=https://example.com/req.txt\n";
        fs::write(&missing, missing_body).expect("missing");
        let parsed = RequirementsParser
            .parse(&missing, missing_body)
            .expect("missing include");
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].name, "kept");
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("was not found")),
            "{:?}",
            parsed.warnings
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("remote include")),
            "{:?}",
            parsed.warnings
        );
    }

    #[test]
    fn variant_names_match_and_unknown_txt_does_not() {
        let accepted = [
            "requirements.txt",
            "REQUIREMENTS.TXT",
            "requirements-dev.txt",
            "requirements-rag.txt",
            "workers/chatbot/requirements-rag.txt",
            "requirements_rag.txt",
            "requirements.dev.txt",
            "app.requirements.txt",
            "requirements/base.txt",
            "Requirements/Foo.TXT",
            "tests/fixtures/pypi/variants/requirements/base.txt",
        ];
        for path in accepted {
            assert!(
                parser_for(Path::new(path)).is_some(),
                "expected a parser for {path}"
            );
        }
        let rejected = [
            "requirements.txt.bak",
            "requirements-dev.txt.bak",
            "myrequirements.txt",
            "notes.txt",
            "not-requirements/notes.txt",
            "requirements/base.json",
        ];
        for path in rejected {
            assert!(
                parser_for(Path::new(path)).is_none(),
                "did not expect a parser for {path}"
            );
        }
    }

    #[test]
    fn variant_fixtures_parse() {
        let cases = [
            (
                "tests/fixtures/pypi/variants/requirements-dev.txt",
                "pytest",
                "8.3.2",
            ),
            (
                "tests/fixtures/pypi/variants/requirements_rag.txt",
                "langchain",
                "0.2.16",
            ),
            (
                "tests/fixtures/pypi/variants/app.requirements.txt",
                "flask",
                "3.0.3",
            ),
            (
                "tests/fixtures/pypi/variants/requirements/base.txt",
                "requests",
                "2.32.3",
            ),
        ];
        for (relative, name, version) in cases {
            let parsed = parse_repo_file(relative);
            assert_eq!(parsed.packages.len(), 1, "{relative}");
            assert_eq!(parsed.packages[0].name, name, "{relative}");
            assert_eq!(parsed.packages[0].version, version, "{relative}");
            assert!(parsed.warnings.is_empty(), "{relative}");
            assert!(
                parser_for(Path::new(relative)).is_some(),
                "explicit path {relative}"
            );
        }
    }
}
