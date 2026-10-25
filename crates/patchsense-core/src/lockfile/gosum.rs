//! Parser for `go.sum`, with `direct` taken from a sibling `go.mod`.
//!
//! Lines ending in `/go.mod` are checksums of the module file, not a package
//! version, so they are skipped. The `v` prefix is kept because OSV's Go
//! ecosystem uses it. A `+incompatible` suffix is removed; OSV does not use it.
//!
//! When `go.mod` is present, a `require` without `// indirect` is direct and
//! a `require` with `// indirect` is transitive. A module that appears only in
//! `go.sum` is transitive. Without `go.mod`, `direct` is `None`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `go.sum`.
pub struct GoSumParser;

impl LockfileParser for GoSumParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Go
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("go.sum"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_go_sum(path, content)
    }
}

fn parse_go_sum(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let mut found: BTreeMap<(String, String), ()> = BTreeMap::new();
    for (index, line) in content.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let module = parts
            .next()
            .ok_or_else(|| CoreError::parse(path, Some(line_no), "go.sum line has no module"))?;
        let version = parts
            .next()
            .ok_or_else(|| CoreError::parse(path, Some(line_no), "go.sum line has no version"))?;
        if version.ends_with("/go.mod") {
            continue;
        }
        let version = normalize_go_version(version);
        found.insert((module.to_string(), version), ());
    }

    let requires = read_go_mod(path)?;
    let source = display_path(path);
    let mut packages: Vec<Package> = found
        .into_keys()
        .map(|(name, version)| {
            let direct = requires
                .as_ref()
                .map(|requires| !requires.get(&name).copied().unwrap_or(true));
            Package {
                ecosystem: Ecosystem::Go,
                name,
                version,
                direct,
                dev: false,
                source_file: source.clone(),
                line: None,
            }
        })
        .collect();
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Go,
        packages,
        warnings: Vec::new(),
    })
}

/// Drop `+incompatible`. Keep the leading `v`.
fn normalize_go_version(version: &str) -> String {
    version
        .strip_suffix("+incompatible")
        .unwrap_or(version)
        .to_string()
}

/// `true` means the module is only required as `// indirect`.
fn read_go_mod(sum_path: &Path) -> Result<Option<BTreeMap<String, bool>>, CoreError> {
    let Some(parent) = sum_path.parent() else {
        return Ok(None);
    };
    let sibling = parent.join("go.mod");
    if !sibling.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(&sibling).map_err(|source| CoreError::Io {
        path: sibling.clone(),
        source,
    })?;
    Ok(Some(parse_go_mod(&text)))
}

fn parse_go_mod(content: &str) -> BTreeMap<String, bool> {
    let mut requires = BTreeMap::new();
    let mut in_block = false;
    for line in content.lines() {
        let indirect = line
            .split("//")
            .nth(1)
            .is_some_and(|comment| comment.split_whitespace().any(|word| word == "indirect"));
        let code = line.split("//").next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }
        if !in_block {
            let Some(rest) = code.strip_prefix("require") else {
                continue;
            };
            let rest = rest.trim();
            if rest.is_empty() || rest == "(" {
                in_block = true;
                continue;
            }
            record_require(&mut requires, rest, indirect);
            continue;
        }
        if code == ")" {
            in_block = false;
            continue;
        }
        record_require(&mut requires, code, indirect);
    }
    requires
}

fn record_require(requires: &mut BTreeMap<String, bool>, spec: &str, indirect: bool) {
    let Some(module) = spec.split_whitespace().next() else {
        return;
    };
    if module == "(" || module == ")" {
        return;
    }
    requires
        .entry(module.to_string())
        .and_modify(|flag| *flag = *flag && indirect)
        .or_insert(indirect);
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
        let relative = format!("tests/fixtures/go/{project}/go.sum");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        let mut parsed = GoSumParser
            .parse(&full, &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"));
        for package in &mut parsed.packages {
            package.source_file = relative.clone();
        }
        parsed
    }

    #[test]
    fn cobra_snapshot_marks_sum_only_modules_transitive() {
        let parsed = parse_fixture("cobra");
        let pflag = parsed
            .packages
            .iter()
            .find(|package| package.name == "github.com/spf13/pflag")
            .expect("pflag");
        assert_eq!(pflag.version, "v1.0.5");
        assert_eq!(pflag.direct, Some(true));
        let check = parsed
            .packages
            .iter()
            .find(|package| package.name == "gopkg.in/check.v1")
            .expect("check");
        assert_eq!(check.direct, Some(false));
        assert_eq!(
            parsed
                .packages
                .iter()
                .filter(|package| package.name == "github.com/spf13/pflag")
                .count(),
            1
        );
        insta::assert_yaml_snapshot!("cobra", parsed);
    }

    #[test]
    fn testify_snapshot_keeps_required_versions_direct() {
        let parsed = parse_fixture("testify");
        let spew = parsed
            .packages
            .iter()
            .find(|package| package.name == "github.com/davecgh/go-spew")
            .expect("go-spew");
        assert_eq!(spew.version, "v1.1.1");
        assert_eq!(spew.direct, Some(true));
        let check = parsed
            .packages
            .iter()
            .find(|package| package.name == "gopkg.in/check.v1")
            .expect("check");
        assert_eq!(check.direct, Some(false));
        insta::assert_yaml_snapshot!("testify", parsed);
    }

    #[test]
    fn indirect_and_incompatible_are_normalized() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/direct/mod v1.2.3\n\tgithub.com/old/mod v1.0.0 // indirect\n)\n",
        )
        .expect("go.mod");
        let sum = "github.com/direct/mod v1.2.3 h1:abc\n\
                   github.com/direct/mod v1.2.3/go.mod h1:def\n\
                   github.com/old/mod v1.0.0+incompatible h1:ghi\n\
                   github.com/old/mod v1.0.0+incompatible/go.mod h1:jkl\n";
        let parsed = GoSumParser
            .parse(&dir.path().join("go.sum"), sum)
            .expect("parse");
        let direct = parsed
            .packages
            .iter()
            .find(|package| package.name == "github.com/direct/mod")
            .expect("direct");
        assert_eq!(direct.direct, Some(true));
        let old = parsed
            .packages
            .iter()
            .find(|package| package.name == "github.com/old/mod")
            .expect("old");
        assert_eq!(old.version, "v1.0.0");
        assert_eq!(old.direct, Some(false));
    }

    #[test]
    fn missing_go_mod_leaves_direct_unknown() {
        let parsed = GoSumParser
            .parse(
                Path::new("missing/go.sum"),
                "github.com/spf13/pflag v1.0.5 h1:abc\n",
            )
            .expect("parse");
        assert_eq!(parsed.packages[0].direct, None);
        assert_eq!(parsed.packages[0].version, "v1.0.5");
    }
}
