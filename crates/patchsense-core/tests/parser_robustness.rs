//! Parsers must return `Ok` or `Err` for truncated fixtures. They must not panic.
//!
//! Cuts are deterministic prefixes of the real fixtures. A short fixed set of
//! garbage strings covers the same nine parsers without a fuzzing dependency.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use patchsense_core::lockfile::{parser_for, supported_file_names};

#[test]
fn truncated_fixtures_do_not_panic() {
    let files = fixture_lockfiles();
    let mut seen = Vec::new();
    assert!(!files.is_empty(), "no fixture lockfiles");
    for file in &files {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .expect("name");
        let parser = parser_for(Path::new(name)).unwrap_or_else(|| panic!("no parser for {name}"));
        seen.push(parser.ecosystem().as_osv_str());
        let content =
            fs::read_to_string(file).unwrap_or_else(|err| panic!("read {}: {err}", file.display()));
        for prefix in prefixes(&content) {
            let result = catch_unwind(AssertUnwindSafe(|| parser.parse(file, prefix)));
            assert!(
                result.is_ok(),
                "panic parsing {} at {} bytes",
                file.display(),
                prefix.len()
            );
        }
    }
    for name in supported_file_names() {
        assert!(
            files.iter().any(|file| {
                file.file_name()
                    .and_then(|file_name| file_name.to_str())
                    .is_some_and(|file_name| file_name.eq_ignore_ascii_case(name))
            }),
            "no fixture exercised {name}"
        );
    }
    let ecosystems: std::collections::BTreeSet<_> = seen.into_iter().collect();
    assert_eq!(
        ecosystems.len(),
        6,
        "expected every ecosystem, got {ecosystems:?}"
    );
}

#[test]
fn garbage_strings_do_not_panic() {
    let garbage = [
        "",
        "\0",
        "{",
        "{]",
        "[[[[",
        "<project>",
        "<project><dependencies>",
        "[[package]]",
        "name =",
        "a: b: c: [",
        "- not a pin",
        "\u{feff}version = 3",
        "packages:\n  /foo@:",
        "__metadata:\n  version: 9\n",
    ];
    for name in supported_file_names() {
        let parser = parser_for(Path::new(name)).unwrap_or_else(|| panic!("no parser for {name}"));
        for sample in garbage {
            let result = catch_unwind(AssertUnwindSafe(|| parser.parse(Path::new(name), sample)));
            assert!(result.is_ok(), "panic parsing {name} sample {sample:?}");
        }
    }
    assert_eq!(supported_file_names().len(), 9);
}

fn fixture_lockfiles() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    files
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if supported_file_names()
            .iter()
            .any(|supported| supported.eq_ignore_ascii_case(name))
        {
            files.push(path);
        }
    }
}

fn prefixes(content: &str) -> Vec<&str> {
    let mut cuts = vec![0, content.len()];
    let step = (content.len() / 16).max(1);
    let mut offset = 0;
    while offset < content.len() {
        cuts.push(offset);
        offset += step;
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts.into_iter()
        .map(|offset| {
            let end = content.floor_char_boundary(offset.min(content.len()));
            &content[..end]
        })
        .collect()
}
