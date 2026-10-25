//! Cursor CLI in print mode. `--force` is omitted, so files stay unchanged.
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

use super::{assert_read_only, json_result, read_prompt, AgentAdapter, AgentError};

/// `agent -p --output-format json`, falling back to `cursor-agent`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CursorAdapter;

impl AgentAdapter for CursorAdapter {
    fn name(&self) -> &'static str {
        "cursor"
    }

    fn binary_candidates(&self) -> &'static [&'static str] {
        &["agent", "cursor-agent"]
    }

    fn build_command(&self, program: &Path, prompt_file: &Path, workdir: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(workdir)
            .arg("-p")
            .arg("--output-format")
            .arg("json")
            .arg(read_prompt(prompt_file));
        command
    }

    fn parse_output(&self, stdout: &str) -> Result<String, AgentError> {
        json_result(stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(command: &Command, dir: &Path) -> String {
        let dir = dir.to_string_lossy().into_owned();
        let mut lines = vec![command
            .get_program()
            .to_string_lossy()
            .replace(&dir, "<dir>")];
        lines.extend(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().replace(&dir, "<dir>")),
        );
        if let Some(current) = command.get_current_dir() {
            lines.push(format!(
                "cwd={}",
                current.to_string_lossy().replace(&dir, "<dir>")
            ));
        }
        lines.join("\n")
    }

    #[test]
    fn command_args_match_the_snapshot() {
        let dir = tempfile::tempdir().expect("temp");
        let prompt = dir.path().join("prompt.txt");
        std::fs::write(&prompt, "explain lodash\n").expect("prompt");
        let command = CursorAdapter.build_command(Path::new("agent"), &prompt, dir.path());
        assert_read_only(&command);
        assert!(!command
            .get_args()
            .any(|arg| arg == "--force" || arg == "--yolo"));
        insta::assert_snapshot!(argv(&command, dir.path()));
    }

    #[test]
    fn parse_output_reads_the_result_field() {
        let stdout = include_str!("../../../../tests/fixtures/agent/cursor.json");
        let text = CursorAdapter.parse_output(stdout).expect("text");
        assert_eq!(text, "Upgrade lodash to 4.17.21.");
        assert_eq!(
            CursorAdapter
                .parse_output("{\"type\":\"result\"}")
                .unwrap_err(),
            AgentError::MissingResult
        );
    }
}
