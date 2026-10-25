//! Lockfile parsers and the registry that picks one from a file name.
//!
//! Parsers are pure: `&str` in, [`ParsedLockfile`] out. Adding an ecosystem
//! means a new type that implements [`LockfileParser`] and an entry in
//! [`PARSERS`].

use std::path::Path;

use crate::error::CoreError;
use crate::model::{Ecosystem, ParsedLockfile};

mod npm;
mod pnpm;
mod poetry;
mod requirements;
mod yarn;

use npm::NpmPackageLockParser;
use pnpm::PnpmParser;
use poetry::PoetryParser;
use requirements::RequirementsParser;
use yarn::YarnParser;

/// A lockfile format PatchSense knows how to read.
pub trait LockfileParser: Send + Sync {
    /// Ecosystem this parser produces.
    fn ecosystem(&self) -> Ecosystem;

    /// Whether `path` is a file this parser owns. Matching uses the file name.
    fn matches(&self, path: &Path) -> bool;

    /// Parse `content` of the lockfile at `path`.
    ///
    /// `path` is only used for error messages and `Package::source_file`.
    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError>;
}

/// File-name parser used until a real parser replaces it.
struct FileNameParser {
    file_name: &'static str,
    ecosystem: Ecosystem,
}

impl LockfileParser for FileNameParser {
    fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(self.file_name))
    }

    fn parse(&self, path: &Path, _content: &str) -> Result<ParsedLockfile, CoreError> {
        Err(CoreError::parse(
            path,
            None,
            format!("parser for {} is not implemented yet", self.file_name),
        ))
    }
}

const NPM_PACKAGE_LOCK: NpmPackageLockParser = NpmPackageLockParser;
const PNPM_LOCK: PnpmParser = PnpmParser;
const YARN_LOCK: YarnParser = YarnParser;
const POETRY_LOCK: PoetryParser = PoetryParser;
const REQUIREMENTS: RequirementsParser = RequirementsParser;
const COMPOSER_LOCK: FileNameParser = FileNameParser {
    file_name: "composer.lock",
    ecosystem: Ecosystem::Packagist,
};
const GO_SUM: FileNameParser = FileNameParser {
    file_name: "go.sum",
    ecosystem: Ecosystem::Go,
};
const POM_XML: FileNameParser = FileNameParser {
    file_name: "pom.xml",
    ecosystem: Ecosystem::Maven,
};
const CARGO_LOCK: FileNameParser = FileNameParser {
    file_name: "Cargo.lock",
    ecosystem: Ecosystem::CratesIo,
};

/// Parsers in the order they are tried. File names in the MVP do not overlap.
static PARSERS: &[&dyn LockfileParser] = &[
    &NPM_PACKAGE_LOCK,
    &PNPM_LOCK,
    &YARN_LOCK,
    &POETRY_LOCK,
    &REQUIREMENTS,
    &COMPOSER_LOCK,
    &GO_SUM,
    &POM_XML,
    &CARGO_LOCK,
];

/// Return the parser for `path`, based on the file name.
pub fn parser_for(path: &Path) -> Option<&'static dyn LockfileParser> {
    PARSERS.iter().copied().find(|parser| parser.matches(path))
}

/// File names the registry recognises, in registry order.
pub fn supported_file_names() -> Vec<&'static str> {
    vec![
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "requirements.txt",
        "composer.lock",
        "go.sum",
        "pom.xml",
        "Cargo.lock",
    ]
}

/// Normalize a PyPI project name per PEP 503.
///
/// The name is lowercased and runs of `-`, `_`, and `.` collapse to a single `-`.
pub fn normalize_pypi_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut last_was_dash = false;
    for ch in name.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_was_dash {
                normalized.push('-');
                last_was_dash = true;
            }
        } else {
            normalized.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn nine_lockfile_names_map_to_osv_ecosystems() {
        let cases = [
            ("package-lock.json", Ecosystem::Npm, "npm"),
            ("pnpm-lock.yaml", Ecosystem::Npm, "npm"),
            ("yarn.lock", Ecosystem::Npm, "npm"),
            ("poetry.lock", Ecosystem::Pypi, "PyPI"),
            ("requirements.txt", Ecosystem::Pypi, "PyPI"),
            ("composer.lock", Ecosystem::Packagist, "Packagist"),
            ("go.sum", Ecosystem::Go, "Go"),
            ("pom.xml", Ecosystem::Maven, "Maven"),
            ("Cargo.lock", Ecosystem::CratesIo, "crates.io"),
        ];
        assert_eq!(cases.len(), 9);
        for (file_name, ecosystem, osv) in cases {
            let path = PathBuf::from("services/api").join(file_name);
            let parser =
                parser_for(&path).unwrap_or_else(|| panic!("missing parser for {file_name}"));
            assert_eq!(parser.ecosystem(), ecosystem, "{file_name}");
            assert_eq!(parser.ecosystem().as_osv_str(), osv, "{file_name}");
            assert!(parser.matches(Path::new(file_name)));
        }
    }

    #[test]
    fn file_name_match_ignores_ascii_case_and_rejects_unknown() {
        let parser =
            parser_for(Path::new("pkg/PACKAGE-LOCK.JSON")).expect("case-insensitive match");
        assert_eq!(parser.ecosystem(), Ecosystem::Npm);
        assert!(parser_for(Path::new("Cargo.toml")).is_none());
        assert!(parser_for(Path::new("requirements-dev.txt")).is_none());
        assert!(parser_for(Path::new("package-lock.json.bak")).is_none());
    }

    #[test]
    fn unimplemented_parser_names_the_file() {
        let path = Path::new("composer.lock");
        let err = parser_for(path)
            .expect("parser")
            .parse(path, "{}")
            .expect_err("stub");
        let message = err.to_string();
        assert!(message.contains("composer.lock"), "{message}");
        assert!(message.contains("not implemented"), "{message}");
    }

    #[test]
    fn pypi_names_follow_pep_503() {
        let cases = [
            ("Requests", "requests"),
            ("Friendly_Bard", "friendly-bard"),
            ("Some..Pkg", "some-pkg"),
            ("A__B--C", "a-b-c"),
            ("foo.bar_baz", "foo-bar-baz"),
            ("already-normal", "already-normal"),
        ];
        for (raw, expected) in cases {
            assert_eq!(normalize_pypi_name(raw), expected, "{raw}");
        }
    }
}
