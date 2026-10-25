//! Claude Code in print mode. No permission-bypass flag is set.

use std::path::Path;
use std::process::Command;

use super::{json_result, read_prompt, AgentAdapter, AgentError};

#[cfg(test)]
use super::assert_read_only;

/// `claude -p --output-format json`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClaudeAdapter;

impl AgentAdapter for ClaudeAdapter {
    fn name(&self) -> &'static str {
        "claude"
    }

    fn binary_candidates(&self) -> &'static [&'static str] {
        &["claude"]
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
        let command = ClaudeAdapter.build_command(Path::new("claude"), &prompt, dir.path());
        assert_read_only(&command);
        assert_eq!(ClaudeAdapter.timeout(), super::super::DEFAULT_TIMEOUT);
        insta::assert_snapshot!(argv(&command, dir.path()));
    }

    #[test]
    fn parse_output_reads_the_result_field() {
        let stdout = include_str!("../../../../tests/fixtures/agent/claude.json");
        let text = ClaudeAdapter.parse_output(stdout).expect("text");
        assert_eq!(text, "Upgrade lodash to 4.17.21.");
        assert_eq!(
            ClaudeAdapter.parse_output("not-json").unwrap_err(),
            AgentError::InvalidJson
        );
    }
}
