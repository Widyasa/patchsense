//! Run one read-only agent for `scan --explain` and attach its text.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use patchsense::config::ExplainAgent;
use patchsense::model::{Explanation, Report};

use super::{find_binary, AgentAdapter, ClaudeAdapter, CodexAdapter, CursorAdapter};

/// Label required next to every AI explanation.
pub const DISCLAIMER: &str = "AI explanation, may be wrong";

/// What `scan --explain` asked the runner to do.
pub struct ExplainRequest<'a> {
    /// `auto` or a named agent. `auto` searches codex, then claude, then cursor.
    pub agent: ExplainAgent,
    /// Findings included in the prompt. They receive the explanation.
    pub top: usize,
    /// Kill the process after this long.
    pub timeout: Duration,
    /// Agent working directory. The scan root.
    pub workdir: &'a Path,
    /// `PATH` to search. `None` reads the process environment.
    pub path: Option<&'a OsStr>,
}

/// Attach an explanation, or record why it did not run.
///
/// A missing agent, a timeout, or a bad response becomes `report.warnings`.
/// The scan's fail-on flag is left alone.
pub fn apply_explain(report: &mut Report, request: &ExplainRequest<'_>) {
    if report.findings.is_empty() || request.top == 0 {
        report.context.explain_status = "ok".to_string();
        return;
    }
    let path_env = std::env::var_os("PATH");
    let path = request.path.or(path_env.as_deref());
    let Some((adapter, program)) = select(request.agent, path) else {
        report.context.explain_status = "no_agent_found".to_string();
        report
            .warnings
            .push("--explain: no agent found on PATH".to_string());
        return;
    };
    let name = adapter.name().to_string();
    report.context.explain_agent = Some(name.clone());
    let prompt = super::build_prompt(report, request.top);
    let scratch = match scratch_dir() {
        Ok(dir) => dir,
        Err(err) => {
            report.context.explain_status = "failed".to_string();
            report
                .warnings
                .push(format!("--explain: failed to prepare the prompt: {err}"));
            return;
        }
    };
    let prompt_file = scratch.join("prompt.txt");
    if let Err(err) = std::fs::write(&prompt_file, prompt) {
        report.context.explain_status = "failed".to_string();
        report
            .warnings
            .push(format!("--explain: failed to write the prompt: {err}"));
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let mut command = adapter.build_command(&program, &prompt_file, request.workdir);
    let captured = capture(&mut command, request.timeout);
    match captured {
        Capture::TimedOut => {
            report.context.explain_status = "timeout".to_string();
            report.warnings.push(format!(
                "--explain: timed out after {}s",
                request.timeout.as_secs().max(1)
            ));
        }
        Capture::Failed(err) => {
            report.context.explain_status = "failed".to_string();
            report.warnings.push(format!("--explain: {err}"));
        }
        Capture::Finished { stdout, status } => {
            let text = agent_text(&adapter, &prompt_file, &stdout);
            match adapter.parse_output(&text) {
                Ok(text) => {
                    let limit = request.top.min(report.findings.len());
                    for finding in report.findings.iter_mut().take(limit) {
                        finding.signals.explanation = Some(Explanation {
                            agent: name.clone(),
                            text: text.clone(),
                            disclaimer: DISCLAIMER.to_string(),
                        });
                    }
                    report.context.explain_status = "ok".to_string();
                    if !status {
                        report.warnings.push(
                            "--explain: agent exited non-zero; the text was still used".to_string(),
                        );
                    }
                }
                Err(err) => {
                    report.context.explain_status = "failed".to_string();
                    report.warnings.push(format!("--explain: {err}"));
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

enum Capture {
    Finished { stdout: String, status: bool },
    TimedOut,
    Failed(String),
}

fn agent_text(adapter: &Chosen, prompt_file: &Path, stdout: &str) -> String {
    if adapter.name() == "codex" && stdout.trim().is_empty() {
        let last = prompt_file.with_file_name("last.md");
        if let Ok(text) = std::fs::read_to_string(last) {
            return text;
        }
    }
    stdout.to_string()
}

fn select(agent: ExplainAgent, path: Option<&OsStr>) -> Option<(Chosen, PathBuf)> {
    let adapters: Vec<Chosen> = match agent {
        ExplainAgent::Auto => vec![
            Chosen::Codex(CodexAdapter),
            Chosen::Claude(ClaudeAdapter),
            Chosen::Cursor(CursorAdapter),
        ],
        ExplainAgent::Codex => vec![Chosen::Codex(CodexAdapter)],
        ExplainAgent::Claude => vec![Chosen::Claude(ClaudeAdapter)],
        ExplainAgent::Cursor => vec![Chosen::Cursor(CursorAdapter)],
    };
    for adapter in adapters {
        if let Some(program) = find_binary(path, adapter.binary_candidates()) {
            return Some((adapter, program));
        }
    }
    None
}

enum Chosen {
    Codex(CodexAdapter),
    Claude(ClaudeAdapter),
    Cursor(CursorAdapter),
}

impl Chosen {
    fn name(&self) -> &'static str {
        match self {
            Self::Codex(adapter) => adapter.name(),
            Self::Claude(adapter) => adapter.name(),
            Self::Cursor(adapter) => adapter.name(),
        }
    }

    fn binary_candidates(&self) -> &'static [&'static str] {
        match self {
            Self::Codex(adapter) => adapter.binary_candidates(),
            Self::Claude(adapter) => adapter.binary_candidates(),
            Self::Cursor(adapter) => adapter.binary_candidates(),
        }
    }

    fn build_command(&self, program: &Path, prompt_file: &Path, workdir: &Path) -> Command {
        match self {
            Self::Codex(adapter) => adapter.build_command(program, prompt_file, workdir),
            Self::Claude(adapter) => adapter.build_command(program, prompt_file, workdir),
            Self::Cursor(adapter) => adapter.build_command(program, prompt_file, workdir),
        }
    }

    fn parse_output(&self, stdout: &str) -> Result<String, super::AgentError> {
        match self {
            Self::Codex(adapter) => adapter.parse_output(stdout),
            Self::Claude(adapter) => adapter.parse_output(stdout),
            Self::Cursor(adapter) => adapter.parse_output(stdout),
        }
    }
}

fn scratch_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "patchsense-explain-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn capture(command: &mut Command, timeout: Duration) -> Capture {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return Capture::Failed(format!("failed to start the agent: {err}")),
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_thread = thread::spawn(move || read_pipe(stdout));
    let stderr_thread = thread::spawn(move || read_pipe(stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status.success()),
            Ok(None) if started.elapsed() >= timeout => {
                kill_child(&mut child);
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(err) => {
                kill_child(&mut child);
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Capture::Failed(err.to_string());
            }
        }
    };
    let stdout = stdout_thread.join().unwrap_or_default();
    let _stderr = stderr_thread.join().unwrap_or_default();
    match status {
        Some(success) => Capture::Finished {
            stdout,
            status: success,
        },
        None => Capture::TimedOut,
    }
}

fn read_pipe(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = String::new();
    let _ = pipe.read_to_string(&mut buf);
    buf
}

fn kill_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let id = child.id();
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{id}")])
            .output();
    }
    let _ = child.kill();
    let _ = child.wait();
}
