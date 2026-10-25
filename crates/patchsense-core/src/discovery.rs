//! Find lockfiles under a directory.
//!
//! Directories named `node_modules`, `vendor`, `target`, `.git`, `.venv`, and
//! `venv` are never entered. Extra glob patterns skip additional paths.
//! Results are sorted so scans are deterministic.

use std::fs;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::error::CoreError;
use crate::lockfile::parser_for;

const SKIP_DIRS: &[&str] = &["node_modules", "vendor", "target", ".git", ".venv", "venv"];

/// Lockfiles under `root`.
///
/// When `root` is a file, that file is returned by itself and exclude globs
/// are not applied. When `root` is a directory, only recognised lockfile names
/// are returned, in sorted relative-path order.
pub fn discover(root: &Path, excludes: &[String]) -> Result<Vec<PathBuf>, CoreError> {
    let metadata = fs::metadata(root).map_err(|source| CoreError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if metadata.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    let globs = compile_excludes(excludes)?;
    let mut found = Vec::new();
    walk(root, root, &globs, &mut found)?;
    found.sort_by_key(|path| rel_slash(root, path));
    Ok(found)
}

fn compile_excludes(excludes: &[String]) -> Result<GlobSet, CoreError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in excludes {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(false)
            .build()
            .map_err(|err| {
                CoreError::parse(
                    PathBuf::from(pattern.as_str()),
                    None,
                    format!("invalid exclude glob: {err}"),
                )
            })?;
        builder.add(glob);
    }
    builder.build().map_err(|err| {
        CoreError::parse(
            PathBuf::from("exclude"),
            None,
            format!("invalid exclude glob: {err}"),
        )
    })
}

fn walk(
    root: &Path,
    dir: &Path,
    globs: &GlobSet,
    found: &mut Vec<PathBuf>,
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
        // Symlinks are not followed. A directory symlink would otherwise
        // re-enter `node_modules` or loop.
        if file_type.is_symlink() {
            continue;
        }
        let rel = rel_slash(root, &path);
        if file_type.is_dir() {
            if is_skipped_dir(&entry.file_name()) || is_excluded(globs, &rel, true) {
                continue;
            }
            walk(root, &path, globs, found)?;
        } else if file_type.is_file()
            && parser_for(&path).is_some()
            && !is_excluded(globs, &rel, false)
        {
            found.push(path);
        }
    }
    Ok(())
}

fn is_skipped_dir(name: &std::ffi::OsStr) -> bool {
    SKIP_DIRS.iter().any(|skip| name == *skip)
}

fn is_excluded(globs: &GlobSet, rel: &str, is_dir: bool) -> bool {
    if globs.is_match(rel) {
        return true;
    }
    // `dir/**` does not match the directory path itself. Probe one child so
    // the directory is skipped instead of walked.
    is_dir && globs.is_match(format!("{rel}/x"))
}

fn rel_slash(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, body).expect("write");
    }

    #[test]
    fn skips_default_directories_honours_exclude_and_sorts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        write(&root.join("package-lock.json"), "{}");
        write(&root.join("z-app/Cargo.lock"), "");
        write(&root.join("a-app/requirements.txt"), "");
        write(&root.join("node_modules/pkg/package-lock.json"), "{}");
        write(&root.join("vendor/composer.lock"), "{}");
        write(&root.join("target/Cargo.lock"), "");
        write(&root.join(".git/package-lock.json"), "{}");
        write(&root.join(".venv/requirements.txt"), "");
        write(&root.join("venv/requirements.txt"), "");
        write(&root.join("skipme/pom.xml"), "<project/>");
        write(&root.join("kept/yarn.lock"), "");
        write(&root.join("kept/notes.txt"), "no");

        let found = discover(root, &["skipme/**".to_string()]).expect("discover");
        let relative: Vec<String> = found.iter().map(|path| rel_slash(root, path)).collect();
        assert_eq!(
            relative,
            vec![
                "a-app/requirements.txt".to_string(),
                "kept/yarn.lock".to_string(),
                "package-lock.json".to_string(),
                "z-app/Cargo.lock".to_string(),
            ]
        );
    }

    #[test]
    fn file_path_returns_only_that_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("node_modules/package-lock.json");
        write(&file, "{}");
        write(&temp.path().join("yarn.lock"), "");
        let found = discover(&file, &[]).expect("discover");
        assert_eq!(found, vec![file]);
    }

    #[test]
    fn invalid_exclude_glob_is_an_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let err = discover(temp.path(), &["[".to_string()]).expect_err("bad glob");
        let message = err.to_string();
        assert!(
            message.contains("exclude") || message.contains("["),
            "{message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_symlinks_are_not_followed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let real = root.join("real");
        write(&real.join("package-lock.json"), "{}");
        std::os::unix::fs::symlink(&real, root.join("alias")).expect("symlink");
        let found = discover(root, &[]).expect("discover");
        let relative: Vec<String> = found.iter().map(|path| rel_slash(root, path)).collect();
        assert_eq!(relative, vec!["real/package-lock.json".to_string()]);
    }
}
