//! Errors produced by `patchsense-core`.
//!
//! The binary crate maps these into `anyhow` errors and an exit code. This
//! crate never prints them itself.

use std::path::PathBuf;

use thiserror::Error;

/// Recoverable failure while reading a project, talking to a data source, or
/// building a report.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Filesystem read or write failed.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Path that could not be read or written.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A lockfile or config file could not be parsed.
    #[error("failed to parse {path}{}: {message}", line.map(|n| format!(":{n}")).unwrap_or_default())]
    Parse {
        /// File that failed to parse.
        path: PathBuf,
        /// Human-readable cause.
        message: String,
        /// 1-based line, when the format exposes one.
        line: Option<usize>,
    },

    /// JSON from a file or an API body was not the shape this crate expects.
    #[error("invalid JSON from {context}: {message}")]
    Json {
        /// File path or URL the JSON came from.
        context: String,
        /// Serde or structural cause.
        message: String,
    },

    /// An HTTP call failed, or the status was not usable after retries.
    #[error("HTTP request to {url} failed: {message}")]
    Http {
        /// Request URL.
        url: String,
        /// Status or transport cause.
        message: String,
    },

    /// Config or CLI named an ecosystem this build does not know.
    #[error("unknown ecosystem `{name}`")]
    UnknownEcosystem {
        /// The name that was rejected.
        name: String,
    },

    /// Scan root contained no supported lockfile.
    #[error("no supported lockfile found in {path}")]
    NoLockfile {
        /// Directory or file that was scanned.
        path: PathBuf,
    },

    /// OSV response was missing a field or disagreed with the request.
    #[error("invalid OSV response from {url}: {message}")]
    Osv {
        /// Endpoint URL.
        url: String,
        /// What was wrong.
        message: String,
    },

    /// The SQLite cache could not be opened or updated.
    #[error("cache error at {path}: {message}")]
    Cache {
        /// Database file.
        path: PathBuf,
        /// SQLite or schema cause.
        message: String,
    },
}

impl CoreError {
    /// Parse error that names `path` and an optional 1-based line.
    pub fn parse(
        path: impl Into<PathBuf>,
        line: Option<usize>,
        message: impl Into<String>,
    ) -> Self {
        Self::Parse {
            path: path.into(),
            message: message.into(),
            line,
        }
    }

    /// JSON error that names the file or URL it came from.
    pub fn json(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Json {
            context: context.into(),
            message: message.into(),
        }
    }
}
