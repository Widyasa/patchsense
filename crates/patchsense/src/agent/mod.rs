//! CLI agent adapters for `scan --explain`.
//!
//! Flag check on 25 Oct 2026:
//! - Codex: `codex exec --sandbox read-only -o <file> <prompt>`
//!   (<https://learn.chatgpt.com/docs/non-interactive-mode>).
//! - Claude Code: `claude -p --output-format json <prompt>`
//!   (<https://code.claude.com/docs/en/headless>).
//! - Cursor: `agent -p --output-format json <prompt>`, then `cursor-agent`.
//!   Print mode does not edit files unless `--force` is set
//!   (<https://cursor.com/docs/cli/headless>).

mod claude;
mod codex;
mod cursor;
mod prompt;
mod run;

pub use run::{apply_explain, ExplainRequest};

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use claude::ClaudeAdapter;
pub use codex::CodexAdapter;
pub use cursor::CursorAdapter;
pub use prompt::build_prompt;

/// Default wait before the runner kills the agent process.
#[cfg_attr(not(test), allow(dead_code))]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Flags and sandbox names that would let an agent write or skip checks.
#[cfg_attr(not(test), allow(dead_code))]
const WRITE_FLAGS: &[&str] = &[
    "--force",
    "--yolo",
    "--dangerously-skip-permissions",
    "--dangerously-bypass-approvals-and-sandbox",
    "danger-full-access",
    "bypassPermissions",
    "workspace-write",
];

/// Failure while reading an agent response. The process is not started here.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentError {
    /// The output was empty.
    Empty,
    /// Claude or Cursor stdout was not JSON.
    InvalidJson,
    /// The JSON object had no string `result`.
    MissingResult,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "agent returned no text"),
            Self::InvalidJson => write!(formatter, "agent JSON was not an object"),
            Self::MissingResult => write!(formatter, "agent JSON had no result string"),
        }
    }
}

impl std::error::Error for AgentError {}

/// One local agent CLI. Implementations do not grant write permission.
pub trait AgentAdapter {
    /// `codex`, `claude`, or `cursor`.
    fn name(&self) -> &'static str;

    /// Executable names, in the order they should be searched on `PATH`.
    fn binary_candidates(&self) -> &'static [&'static str];

    /// How long the runner waits before killing the process.
    #[cfg_attr(not(test), allow(dead_code))]
    fn timeout(&self) -> Duration {
        DEFAULT_TIMEOUT
    }

    /// Build a read-only command. `program` is the binary chosen from `PATH`.
    ///
    /// The prompt file is read and passed as the final argument. The command
    /// does not include a flag that allows writes.
    fn build_command(
        &self,
        program: &Path,
        prompt_file: &Path,
        workdir: &Path,
    ) -> std::process::Command;

    /// Turn captured stdout into the explanation text.
    fn parse_output(&self, stdout: &str) -> Result<String, AgentError>;
}

/// First candidate that exists as a file on `path`.
///
/// `path` uses the platform `PATH` separator. On Windows a `.exe` suffix is
/// also tried. Cursor's order is `agent`, then `cursor-agent`.
pub fn find_binary(path: Option<&OsStr>, candidates: &[&str]) -> Option<PathBuf> {
    let path = path?;
    for name in candidates {
        for dir in std::env::split_paths(path) {
            let direct = dir.join(name);
            if direct.is_file() {
                return Some(direct);
            }
            #[cfg(windows)]
            {
                for suffix in ["exe", "bat", "cmd"] {
                    let candidate = dir.join(format!("{name}.{suffix}"));
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn read_prompt(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub(crate) fn json_result(stdout: &str) -> Result<String, AgentError> {
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|_| AgentError::InvalidJson)?;
    value
        .get("result")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or(AgentError::MissingResult)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn assert_read_only(command: &std::process::Command) {
    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    for flag in WRITE_FLAGS {
        assert!(
            !args.iter().any(|arg| arg == flag),
            "write flag {flag} in {args:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_search_prefers_agent_then_cursor_agent() {
        let root = tempfile::tempdir().expect("temp");
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir(&first).expect("dir");
        std::fs::create_dir(&second).expect("dir");
        std::fs::write(second.join("cursor-agent"), "").expect("file");
        let path = std::env::join_paths([&first, &second]).expect("path");
        let found = find_binary(Some(path.as_os_str()), CursorAdapter.binary_candidates())
            .expect("cursor-agent");
        assert_eq!(found, second.join("cursor-agent"));

        std::fs::write(first.join("agent"), "").expect("file");
        let path = std::env::join_paths([&first, &second]).expect("path");
        let found =
            find_binary(Some(path.as_os_str()), CursorAdapter.binary_candidates()).expect("agent");
        assert_eq!(found, first.join("agent"));
    }
}
