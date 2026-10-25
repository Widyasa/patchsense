//! Parser for `Cargo.lock`.
//!
//! Only crates.io packages are emitted. A package is crates.io when `source`
//! is `registry+https://github.com/rust-lang/crates.io-index` or
//! `sparse+https://index.crates.io/`. Path packages (no `source`, or
//! `path+...`) and `git+...` sources are skipped. Other registries are skipped
//! with a warning.
//!
//! `direct` comes from a sibling `Cargo.toml` when one exists, including
//! `[workspace] members` (literal paths and globs). `[dependencies]` and
//! `[build-dependencies]`, including target-specific tables, are direct and
//! not dev. `[dev-dependencies]` are direct and dev, unless the same crate is
//! also a normal or build dependency. The crates.io name is the `package` key
//! when a dependency is renamed. Without `Cargo.toml`, `direct` is `None`.
//!
//! Every published version of a directly named crate is marked direct. Cargo
//! does not record, in `Cargo.toml`, which lockfile version was the direct one.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use globset::GlobBuilder;
use serde::Deserialize;

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// Parser for `Cargo.lock`.
pub struct CargoLockParser;

impl LockfileParser for CargoLockParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::CratesIo
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("Cargo.lock"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_cargo_lock(path, content)
    }
}

#[derive(Debug, Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Default)]
struct ManifestDeps {
    normal: BTreeSet<String>,
    dev: BTreeSet<String>,
    build: BTreeSet<String>,
}

enum DepKind {
    Normal,
    Dev,
    Build,
}

fn parse_cargo_lock(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let lock: CargoLock = toml::from_str(content).map_err(|err| {
        CoreError::parse(
            path,
            toml_line(content, &err),
            format!("invalid Cargo.lock: {err}"),
        )
    })?;
    let source = display_path(path);
    let mut warnings = Vec::new();
    let manifests = load_manifest_deps(path, &source, &mut warnings);
    let mut packages = Vec::new();
    for package in lock.package {
        if package.name.is_empty() || package.version.is_empty() {
            warnings.push(format!(
                "{source}: package entry missing name or version, skipped"
            ));
            continue;
        }
        let Some(origin) = package.source.as_deref() else {
            continue;
        };
        if !is_crates_io(origin) {
            if !origin.starts_with("git+") && !origin.starts_with("path+") {
                warnings.push(format!(
                    "{source}: skipped {}@{} from non-crates.io source `{origin}`",
                    package.name, package.version
                ));
            }
            continue;
        }
        let (direct, dev) = classify(&package.name, manifests.as_ref());
        packages.push(Package {
            ecosystem: Ecosystem::CratesIo,
            name: package.name,
            version: package.version,
            direct,
            dev,
            source_file: source.clone(),
            line: None,
        });
    }
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::CratesIo,
        packages,
        warnings,
    })
}

fn is_crates_io(source: &str) -> bool {
    let Some(rest) = source
        .strip_prefix("registry+")
        .or_else(|| source.strip_prefix("sparse+"))
    else {
        return false;
    };
    rest.starts_with("https://github.com/rust-lang/crates.io-index")
        || rest.starts_with("https://index.crates.io/")
        || rest == "https://index.crates.io"
}

fn classify(name: &str, manifests: Option<&ManifestDeps>) -> (Option<bool>, bool) {
    let Some(manifests) = manifests else {
        return (None, false);
    };
    let normal = manifests.normal.contains(name) || manifests.build.contains(name);
    let dev = manifests.dev.contains(name) && !normal;
    let direct = normal || manifests.dev.contains(name);
    (Some(direct), dev)
}

fn load_manifest_deps(
    lock_path: &Path,
    label: &str,
    warnings: &mut Vec<String>,
) -> Option<ManifestDeps> {
    let root = lock_path.parent()?;
    let manifest_path = root.join("Cargo.toml");
    if !manifest_path.is_file() {
        return None;
    }
    let doc = read_manifest(&manifest_path, label, warnings)?;
    let mut deps = ManifestDeps::default();
    walk_manifest(&doc, None, &mut deps);
    let Some(members) = doc
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
    else {
        return Some(deps);
    };
    for member in members {
        let Some(pattern) = member.as_str() else {
            continue;
        };
        for dir in member_dirs(root, pattern, label, warnings) {
            let path = dir.join("Cargo.toml");
            if !path.is_file() {
                if !is_glob(pattern) {
                    warnings.push(format!(
                        "{label}: workspace member `{pattern}` has no Cargo.toml"
                    ));
                }
                continue;
            }
            if let Some(member_doc) = read_manifest(&path, label, warnings) {
                walk_manifest(&member_doc, None, &mut deps);
            }
        }
    }
    Some(deps)
}

fn read_manifest(path: &Path, label: &str, warnings: &mut Vec<String>) -> Option<toml::Value> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            warnings.push(format!(
                "{label}: failed to read {}: {err}",
                display_path(path)
            ));
            return None;
        }
    };
    match toml::from_str(&text) {
        Ok(value) => Some(value),
        Err(err) => {
            warnings.push(format!(
                "{label}: failed to parse {}: {err}",
                display_path(path)
            ));
            None
        }
    }
}

fn walk_manifest(value: &toml::Value, parent: Option<&str>, deps: &mut ManifestDeps) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        if parent != Some("workspace") {
            if let Some(kind) = dep_kind(key) {
                collect_dep_table(child, kind, deps);
            }
        }
        walk_manifest(child, Some(key), deps);
    }
}

fn dep_kind(key: &str) -> Option<DepKind> {
    match key {
        "dependencies" => Some(DepKind::Normal),
        "dev-dependencies" => Some(DepKind::Dev),
        "build-dependencies" => Some(DepKind::Build),
        _ => None,
    }
}

fn collect_dep_table(value: &toml::Value, kind: DepKind, deps: &mut ManifestDeps) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, spec) in table {
        let name = spec
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(key);
        match kind {
            DepKind::Normal => deps.normal.insert(name.to_string()),
            DepKind::Dev => deps.dev.insert(name.to_string()),
            DepKind::Build => deps.build.insert(name.to_string()),
        };
    }
}

fn member_dirs(
    root: &Path,
    pattern: &str,
    label: &str,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    if !is_glob(pattern) {
        return vec![root.join(pattern)];
    }
    let glob = match GlobBuilder::new(pattern).literal_separator(true).build() {
        Ok(glob) => glob,
        Err(err) => {
            warnings.push(format!(
                "{label}: invalid workspace member glob `{pattern}`: {err}"
            ));
            return Vec::new();
        }
    };
    let matcher = glob.compile_matcher();
    let mut found = Vec::new();
    walk_member_dirs(root, root, &matcher, &mut found, 0);
    found
}

fn walk_member_dirs(
    root: &Path,
    dir: &Path,
    matcher: &globset::GlobMatcher,
    found: &mut Vec<PathBuf>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == ".git" {
            continue;
        }
        let path = entry.path();
        if let Ok(relative) = path.strip_prefix(root) {
            let relative = relative.to_string_lossy().replace('\\', "/");
            if matcher.is_match(&relative) {
                found.push(path.clone());
            }
        }
        walk_member_dirs(root, &path, matcher, found, depth + 1);
    }
}

fn is_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '['])
}

fn toml_line(content: &str, err: &toml::de::Error) -> Option<usize> {
    let span = err.span()?;
    Some(
        content[..span.start.min(content.len())]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1,
    )
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

    fn parse_fixture(project: &str) -> ParsedLockfile {
        let relative = format!("tests/fixtures/cargo/{project}/Cargo.lock");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        let mut parsed = CargoLockParser
            .parse(&full, &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"));
        for package in &mut parsed.packages {
            package.source_file = relative.clone();
        }
        parsed
    }

    fn package<'a>(parsed: &'a ParsedLockfile, name: &str) -> &'a Package {
        parsed
            .packages
            .iter()
            .find(|package| package.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    #[test]
    fn ripgrep_marks_workspace_members_and_skips_path_crates() {
        let parsed = parse_fixture("ripgrep");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let anyhow = package(&parsed, "anyhow");
        assert_eq!(anyhow.version, "1.0.87");
        assert_eq!(anyhow.direct, Some(true));
        assert!(!anyhow.dev);
        let memmap = package(&parsed, "memmap2");
        assert_eq!(memmap.direct, Some(true));
        assert!(!memmap.dev);
        let regex = package(&parsed, "regex");
        assert_eq!(regex.direct, Some(true));
        assert!(regex.dev);
        let jemallocator = package(&parsed, "jemallocator");
        assert_eq!(jemallocator.direct, Some(true));
        assert!(!jemallocator.dev);
        let itoa = package(&parsed, "itoa");
        assert_eq!(itoa.direct, Some(false));
        assert!(!itoa.dev);
        assert!(parsed
            .packages
            .iter()
            .all(|package| package.name != "globset"));
        assert!(parsed.packages.iter().all(|package| package.name != "grep"));
        insta::assert_yaml_snapshot!("ripgrep", parsed.packages);
    }

    #[test]
    fn patchsense_lockfile_marks_member_dev_dependencies() {
        let parsed = parse_fixture("patchsense");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let anyhow = package(&parsed, "anyhow");
        assert_eq!(anyhow.direct, Some(true));
        assert!(!anyhow.dev);
        let quick_xml = package(&parsed, "quick-xml");
        assert_eq!(quick_xml.direct, Some(true));
        assert!(!quick_xml.dev);
        let assert_cmd = package(&parsed, "assert_cmd");
        assert_eq!(assert_cmd.direct, Some(true));
        assert!(assert_cmd.dev);
        let insta_pkg = package(&parsed, "insta");
        assert_eq!(insta_pkg.direct, Some(true));
        assert!(insta_pkg.dev);
        let memchr = package(&parsed, "memchr");
        assert_eq!(memchr.direct, Some(false));
        assert!(parsed
            .packages
            .iter()
            .all(|package| package.name != "patchsense" && package.name != "patchsense-core"));
        insta::assert_yaml_snapshot!("patchsense", parsed.packages);
    }

    #[test]
    fn missing_manifest_git_and_sparse_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = "\
version = 4

[[package]]
name = \"local\"
version = \"0.1.0\"

[[package]]
name = \"from-git\"
version = \"1.2.3\"
source = \"git+https://github.com/example/from-git?rev=abc\"

[[package]]
name = \"other-reg\"
version = \"0.1.0\"
source = \"registry+https://example.com/index\"

[[package]]
name = \"serde\"
version = \"1.0.210\"
source = \"sparse+https://index.crates.io/\"
";
        let parsed = CargoLockParser
            .parse(&dir.path().join("Cargo.lock"), lock)
            .expect("parse");
        assert_eq!(parsed.packages.len(), 1);
        assert_eq!(parsed.packages[0].name, "serde");
        assert_eq!(parsed.packages[0].direct, None);
        assert!(!parsed.packages[0].dev);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("other-reg")),
            "{:?}",
            parsed.warnings
        );
    }

    #[test]
    fn workspace_glob_and_build_dependencies() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .expect("root");
        fs::create_dir_all(dir.path().join("crates/app")).expect("member");
        fs::write(
            dir.path().join("crates/app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nanyhow = \"1\"\n\n[build-dependencies]\ncc = \"1\"\n\n[dev-dependencies]\ntempfile = \"3\"\nanyhow = \"1\"\n",
        )
        .expect("member toml");
        let lock = "\
version = 3

[[package]]
name = \"anyhow\"
version = \"1.0.86\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"

[[package]]
name = \"app\"
version = \"0.1.0\"

[[package]]
name = \"cc\"
version = \"1.1.18\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"

[[package]]
name = \"tempfile\"
version = \"3.12.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
";
        let parsed = CargoLockParser
            .parse(&dir.path().join("Cargo.lock"), lock)
            .expect("parse");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let anyhow = package(&parsed, "anyhow");
        assert_eq!(anyhow.direct, Some(true));
        assert!(!anyhow.dev);
        let cc = package(&parsed, "cc");
        assert_eq!(cc.direct, Some(true));
        assert!(!cc.dev);
        let tempfile = package(&parsed, "tempfile");
        assert_eq!(tempfile.direct, Some(true));
        assert!(tempfile.dev);
        assert!(parsed.packages.iter().all(|package| package.name != "app"));
    }

    #[test]
    fn broken_lockfile_names_the_file() {
        let err = CargoLockParser
            .parse(Path::new("Cargo.lock"), "[[package]\n")
            .expect_err("broken");
        let message = err.to_string();
        assert!(message.contains("Cargo.lock"), "{message}");
    }
}
