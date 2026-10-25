//! OpenAI Codex CLI. `exec` stays in the read-only sandbox.

use std::path::Path;
use std::process::Command;

use super::{read_prompt, AgentAdapter, AgentError};

#[cfg(test)]
use super::assert_read_only;

/// `codex exec --sandbox read-only`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodexAdapter;

impl AgentAdapter for CodexAdapter {
    fn name(&self) -> &'static str {
        "codex"
    }

    fn binary_candidates(&self) -> &'static [&'static str] {
        &["codex"]
    }

    fn build_command(&self, program: &Path, prompt_file: &Path, workdir: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(workdir)
            .arg("exec")
            .arg("--sandbox")
            .arg("read-only")
            .arg("-o")
            .arg(prompt_file.with_file_name("last.md"))
            .arg(read_prompt(prompt_file));
        command
    }

    fn parse_output(&self, stdout: &str) -> Result<String, AgentError> {
        let text = stdout.trim();
        if text.is_empty() {
            Err(AgentError::Empty)
        } else {
            Ok(text.to_string())
        }
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
        let command = CodexAdapter.build_command(Path::new("codex"), &prompt, dir.path());
        assert_read_only(&command);
        insta::assert_snapshot!(argv(&command, dir.path()));
    }

    #[test]
    fn parse_output_reads_the_fixture() {
        let stdout = include_str!("../../../../tests/fixtures/agent/codex_last.md");
        let text = CodexAdapter.parse_output(stdout).expect("text");
        assert_eq!(text, "Upgrade lodash to 4.17.21.");
    }
}
