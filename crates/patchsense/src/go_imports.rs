//! Package-level import check for Go findings.
//!
//! OSV records the vulnerable import path on
//! `affected[].ecosystem_specific.imports`. A `go.sum` hit only proves the
//! module version. This module reads `.go` files and, when none of those
//! paths appear, sets [`Finding::import_note`] to [`IMPORT_NOT_SEEN`].
//!
//! The score and tier stay as they were. A missing import is not proof the
//! package is unused: the scan skips tests and vendor trees, it does not
//! evaluate build tags, and it cannot see files created at build time.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::error::CoreError;
use crate::model::{Ecosystem, Finding};

/// Note attached when a Go advisory lists import paths and none were found.
pub const IMPORT_NOT_SEEN: &str = "imported package not seen";

/// Which `.go` files the import scan ignores. All three default to skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoImportFilter {
    /// Skip a directory named `vendor`.
    pub skip_vendor: bool,
    /// Skip a directory named `testdata`.
    pub skip_testdata: bool,
    /// Skip files whose names end in `_test.go`.
    pub skip_tests: bool,
}

impl Default for GoImportFilter {
    fn default() -> Self {
        Self {
            skip_vendor: true,
            skip_testdata: true,
            skip_tests: true,
        }
    }
}

/// `true` when `import_path` is `advisory_path` or a package under it.
///
/// Importing a parent does not count. `golang.org/x/crypto` does not match
/// an advisory path of `golang.org/x/crypto/openpgp`.
pub fn path_matches(advisory_path: &str, import_path: &str) -> bool {
    if advisory_path.is_empty() {
        return false;
    }
    import_path == advisory_path
        || import_path
            .strip_prefix(advisory_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Set [`IMPORT_NOT_SEEN`] on Go findings whose listed paths are absent.
///
/// Findings with an empty `imports` list are left unchanged, including when
/// the tree has no `.go` files. A walk error is a warning and does not add
/// the note, so a partial tree is not reported as "not seen".
pub fn annotate_findings(
    findings: &mut [Finding],
    root: &Path,
    filter: &GoImportFilter,
    warnings: &mut Vec<String>,
) {
    let needs = findings.iter().any(|finding| {
        finding.package.ecosystem == Ecosystem::Go && !finding.advisory.imports.is_empty()
    });
    if !needs {
        return;
    }
    let scan_root = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    if !scan_root.is_dir() {
        warnings.push(format!(
            "go import scan skipped: {} is not a directory",
            scan_root.display()
        ));
        return;
    }
    let found = match collect_imports(scan_root, filter, warnings) {
        Ok(found) => found,
        Err(err) => {
            warnings.push(format!("go import scan failed: {err}"));
            return;
        }
    };
    for finding in findings.iter_mut() {
        if finding.package.ecosystem != Ecosystem::Go || finding.advisory.imports.is_empty() {
            continue;
        }
        let seen = finding.advisory.imports.iter().any(|item| {
            found
                .iter()
                .any(|imported| path_matches(&item.path, imported))
        });
        if !seen {
            finding.import_note = Some(IMPORT_NOT_SEEN.to_string());
        }
    }
}

/// Import paths from `.go` files under `root`.
///
/// Directory symlinks are not followed. `vendor`, `testdata`, and `*_test.go`
/// follow `filter`. `node_modules`, `target`, `.git`, `.venv`, and `venv` are
/// always skipped, matching lockfile discovery.
pub fn collect_imports(
    root: &Path,
    filter: &GoImportFilter,
    warnings: &mut Vec<String>,
) -> Result<BTreeSet<String>, CoreError> {
    let mut found = BTreeSet::new();
    walk(root, filter, &mut found, warnings)?;
    Ok(found)
}

fn walk(
    dir: &Path,
    filter: &GoImportFilter,
    found: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Result<(), CoreError> {
    let entries = fs::read_dir(dir).map_err(|source| CoreError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CoreError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| CoreError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if skipped_dir(&entry.file_name(), filter) {
                continue;
            }
            walk(&path, filter, found, warnings)?;
        } else if file_type.is_file() && is_go_source(&entry.file_name(), filter) {
            match fs::read_to_string(&path) {
                Ok(text) => found.extend(parse_go_imports(&text)),
                Err(err) => warnings.push(format!("skipped {}: {err}", path.display())),
            }
        }
    }
    Ok(())
}

fn skipped_dir(name: &std::ffi::OsStr, filter: &GoImportFilter) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(name, "node_modules" | "target" | ".git" | ".venv" | "venv")
        || (filter.skip_vendor && name == "vendor")
        || (filter.skip_testdata && name == "testdata")
}

fn is_go_source(name: &std::ffi::OsStr, filter: &GoImportFilter) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    if !name.ends_with(".go") {
        return false;
    }
    if filter.skip_tests && name.ends_with("_test.go") {
        return false;
    }
    true
}

/// Paths from `import` declarations. Build-tag comments are ignored, so the
/// imports in a tagged file are still collected. Aliases, `.`, and `_` do
/// not change the path.
pub fn parse_go_imports(text: &str) -> BTreeSet<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut index = 0;
    skip_gap(text, &mut index);
    let Some((word, next)) = take_ident(text, index) else {
        return BTreeSet::new();
    };
    if word != "package" {
        return BTreeSet::new();
    }
    index = next;
    skip_gap(text, &mut index);
    let Some((_, next)) = take_ident(text, index) else {
        return BTreeSet::new();
    };
    index = next;
    let mut paths = BTreeSet::new();
    loop {
        skip_gap(text, &mut index);
        if index >= text.len() {
            break;
        }
        if text[index..].starts_with(';') {
            index += 1;
            continue;
        }
        let Some((word, next)) = take_ident(text, index) else {
            break;
        };
        if word != "import" {
            break;
        }
        index = next;
        skip_gap(text, &mut index);
        if text[index..].starts_with('(') {
            index += 1;
            parse_import_block(text, &mut index, &mut paths);
        } else if !parse_import_spec(text, &mut index, &mut paths) {
            break;
        }
    }
    paths
}

fn parse_import_block(text: &str, index: &mut usize, paths: &mut BTreeSet<String>) {
    loop {
        skip_gap(text, index);
        if *index >= text.len() {
            break;
        }
        if text[*index..].starts_with(')') {
            *index += 1;
            break;
        }
        if text[*index..].starts_with(';') {
            *index += 1;
            continue;
        }
        if !parse_import_spec(text, index, paths) {
            if let Some(ch) = text[*index..].chars().next() {
                *index += ch.len_utf8();
            } else {
                break;
            }
        }
    }
}

fn parse_import_spec(text: &str, index: &mut usize, paths: &mut BTreeSet<String>) -> bool {
    skip_gap(text, index);
    if *index >= text.len() {
        return false;
    }
    if text[*index..].starts_with('.') {
        *index += 1;
        skip_gap(text, index);
        return take_import_path(text, index, paths);
    }
    if let Some((_, next)) = take_ident(text, *index) {
        *index = next;
        skip_gap(text, index);
        return take_import_path(text, index, paths);
    }
    take_import_path(text, index, paths)
}

fn take_import_path(text: &str, index: &mut usize, paths: &mut BTreeSet<String>) -> bool {
    let Some((path, next)) = take_string(text, *index) else {
        return false;
    };
    *index = next;
    if !path.is_empty() {
        paths.insert(path);
    }
    true
}

fn skip_gap(text: &str, index: &mut usize) {
    loop {
        while let Some(ch) = text[*index..].chars().next() {
            if ch.is_whitespace() {
                *index += ch.len_utf8();
            } else {
                break;
            }
        }
        if text[*index..].starts_with("//") {
            if let Some(end) = text[*index..].find('\n') {
                *index += end + 1;
            } else {
                *index = text.len();
            }
            continue;
        }
        if text[*index..].starts_with("/*") {
            if let Some(end) = text[*index..].find("*/") {
                *index += end + 2;
            } else {
                *index = text.len();
            }
            continue;
        }
        break;
    }
}

fn take_ident(text: &str, index: usize) -> Option<(String, usize)> {
    let mut chars = text[index..].chars();
    let first = chars.next()?;
    if first != '_' && !first.is_alphabetic() {
        return None;
    }
    let mut end = index + first.len_utf8();
    for ch in chars {
        if ch == '_' || ch.is_alphanumeric() {
            end += ch.len_utf8();
        } else {
            break;
        }
    }
    Some((text[index..end].to_string(), end))
}

fn take_string(text: &str, index: usize) -> Option<(String, usize)> {
    let rest = text.get(index..)?;
    if rest.starts_with('"') {
        let mut out = String::new();
        let mut cursor = index + 1;
        while cursor < text.len() {
            let ch = text[cursor..].chars().next()?;
            if ch == '"' {
                return Some((out, cursor + 1));
            }
            if ch == '\n' {
                return None;
            }
            if ch == '\\' {
                let escaped = text[cursor + 1..].chars().next()?;
                match escaped {
                    '\\' | '"' | '\'' => out.push(escaped),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    other => out.push(other),
                }
                cursor += 1 + escaped.len_utf8();
                continue;
            }
            out.push(ch);
            cursor += ch.len_utf8();
        }
        return None;
    }
    if rest.starts_with('`') {
        let start = index + 1;
        let end = text[start..].find('`')?;
        return Some((text[start..start + end].to_string(), start + end + 1));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Advisory, FindingSignals, Package, Tier};

    #[test]
    fn parser_keeps_alias_dot_blank_and_build_tags() {
        let source = r#"
//go:build linux && amd64
// +build linux,amd64

package main

import "fmt"
import argon2 "golang.org/x/crypto/argon2"
import (
    . "golang.org/x/crypto/openpgp/packet"
    _ "golang.org/x/crypto/openpgp/armor"
    pgp "golang.org/x/crypto/openpgp"
)

func main() {}
"#;
        let paths = parse_go_imports(source);
        assert!(paths.contains("fmt"));
        assert!(paths.contains("golang.org/x/crypto/argon2"));
        assert!(paths.contains("golang.org/x/crypto/openpgp/packet"));
        assert!(paths.contains("golang.org/x/crypto/openpgp/armor"));
        assert!(paths.contains("golang.org/x/crypto/openpgp"));
        assert_eq!(paths.len(), 5);
    }

    #[test]
    fn raw_import_string_and_commented_import_are_handled() {
        let source = "package p\nimport `golang.org/x/crypto/openpgp`\n// import \"ignored\"\n";
        let paths = parse_go_imports(source);
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            vec!["golang.org/x/crypto/openpgp".to_string()]
        );
    }

    #[test]
    fn subpackage_prefix_matches_and_a_parent_import_does_not() {
        assert!(path_matches(
            "golang.org/x/crypto/openpgp",
            "golang.org/x/crypto/openpgp"
        ));
        assert!(path_matches(
            "golang.org/x/crypto/openpgp",
            "golang.org/x/crypto/openpgp/packet"
        ));
        assert!(!path_matches(
            "golang.org/x/crypto/openpgp",
            "golang.org/x/crypto/openpgp2"
        ));
        assert!(!path_matches(
            "golang.org/x/crypto/openpgp",
            "golang.org/x/crypto"
        ));
        assert!(!path_matches(
            "golang.org/x/crypto/openpgp",
            "golang.org/x/crypto/argon2"
        ));
    }

    #[test]
    fn skipped_files_do_not_count_and_the_filter_can_include_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("vendor")).expect("vendor");
        fs::create_dir_all(dir.path().join("testdata")).expect("testdata");
        fs::write(
            dir.path().join("main.go"),
            "package main\nimport argon2 \"golang.org/x/crypto/argon2\"\n",
        )
        .expect("main");
        fs::write(
            dir.path().join("crypto_test.go"),
            "package main\nimport \"golang.org/x/crypto/openpgp\"\n",
        )
        .expect("test");
        fs::write(
            dir.path().join("vendor/extra.go"),
            "package extra\nimport \"golang.org/x/crypto/openpgp\"\n",
        )
        .expect("vendor");
        fs::write(
            dir.path().join("testdata/sample.go"),
            "package sample\nimport \"golang.org/x/crypto/openpgp\"\n",
        )
        .expect("testdata");

        let mut warnings = Vec::new();
        let skipped =
            collect_imports(dir.path(), &GoImportFilter::default(), &mut warnings).expect("scan");
        assert!(skipped.contains("golang.org/x/crypto/argon2"));
        assert!(!skipped.contains("golang.org/x/crypto/openpgp"));

        let included = collect_imports(
            dir.path(),
            &GoImportFilter {
                skip_vendor: false,
                skip_testdata: false,
                skip_tests: false,
            },
            &mut warnings,
        )
        .expect("include");
        assert!(included.contains("golang.org/x/crypto/openpgp"));
    }

    #[test]
    fn missing_import_sets_the_note_without_changing_the_score() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("main.go"),
            "package main\nimport argon2 \"golang.org/x/crypto/argon2\"\n",
        )
        .expect("main");
        let mut findings = vec![
            go_finding("GO-2026-5932", vec!["golang.org/x/crypto/openpgp"], 20),
            go_finding("GO-2099-0001", Vec::new(), 20),
        ];
        let mut warnings = Vec::new();
        annotate_findings(
            &mut findings,
            dir.path(),
            &GoImportFilter::default(),
            &mut warnings,
        );
        assert_eq!(findings[0].import_note.as_deref(), Some(IMPORT_NOT_SEEN));
        assert_eq!(findings[0].score, 20);
        assert!(findings[1].import_note.is_none());
        assert_eq!(findings[1].score, 20);
        assert!(warnings.is_empty());
    }

    #[test]
    fn an_imported_subpackage_clears_the_note() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("packet.go"),
            "//go:build ignore\n\npackage main\n\nimport pgp \"golang.org/x/crypto/openpgp/packet\"\n",
        )
        .expect("packet");
        let mut findings = vec![go_finding(
            "GO-2026-5932",
            vec!["golang.org/x/crypto/openpgp"],
            41,
        )];
        annotate_findings(
            &mut findings,
            dir.path(),
            &GoImportFilter::default(),
            &mut Vec::new(),
        );
        assert!(findings[0].import_note.is_none());
        assert_eq!(findings[0].score, 41);
    }

    fn go_finding(id: &str, paths: Vec<&str>, score: u32) -> Finding {
        Finding {
            advisory: Advisory {
                id: id.to_string(),
                aliases: Vec::new(),
                summary: "summary".to_string(),
                severity: Vec::new(),
                database_specific_severity: None,
                references: Vec::new(),
                fixed_versions: vec!["0.45.0".to_string()],
                imports: paths
                    .into_iter()
                    .map(|path| crate::model::GoImport {
                        path: path.to_string(),
                        symbols: vec!["ReadMessage".to_string()],
                    })
                    .collect(),
            },
            package: Package {
                ecosystem: Ecosystem::Go,
                name: "golang.org/x/crypto".to_string(),
                version: "v0.31.0".to_string(),
                direct: None,
                dev: false,
                source_file: "go.sum".to_string(),
                source_files: Vec::new(),
                line: None,
            },
            tier: Tier::Defer,
            score,
            signals: FindingSignals::default(),
            import_note: None,
        }
    }
}
