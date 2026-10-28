//! `patchsense init` writes the example config from PRD §7.

use std::path::Path;

use anyhow::Context;

/// Example `patchsense.toml` printed by `patchsense init`.
pub const EXAMPLE_CONFIG: &str = r#"# patchsense.toml
schema_version = 1

[scan]
ecosystems = ["npm", "pypi", "packagist", "go", "maven", "cargo"]
exclude = ["examples/**", "fixtures/**"]
include_dev = true
fail_on = "critical"

[scan.go_imports]
skip_vendor = true
skip_testdata = true
skip_tests = true

[score.weights]
kev = 35
epss = 25
cvss = 20
direct = 10
fix_available = 10

[score.epss]
mode = "probability"
saturation = 0.10

[score.thresholds]
critical = 70
review = 40

[score.unknown_direct]
weight_fraction = 1.0

[cache]
ttl_hours_osv = 24
ttl_hours_epss = 24
ttl_hours_kev = 24
# Expired EPSS and KEV stay in an offline score, with a warning. true exits 2.
strict_cache = false

[output]
top = 20

[explain]
agent = "auto"
top = 10
timeout_secs = 120

[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Used only in a build script, not exposed"
expires = "2027-01-31"
"#;

/// What `write_example_config` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStatus {
    /// The file was not there and was created.
    Created,
    /// The file was already there and `--force` was not set.
    Kept,
    /// `--force` replaced an existing file.
    Replaced,
}

/// Opening marker for the agent instruction block.
pub const START_MARKER: &str = "<!-- patchsense:start -->";

/// Closing marker for the agent instruction block.
pub const END_MARKER: &str = "<!-- patchsense:end -->";

/// Instruction block from PRD §12.1, including both markers.
pub const INSTRUCTION_BLOCK: &str = "\
<!-- patchsense:start -->
## Dependency security (PatchSense)
- Before adding or upgrading a dependency, run `patchsense scan . --format json` or call the MCP tool `scan_project`.
- Prioritize `critical` findings, then `review`. Use `get_fix_plan` for the fixed version.
- Always include advisory links from the scan. Do not invent fixed versions.
<!-- patchsense:end -->
";

/// Frontmatter for a new `.cursor/rules/patchsense.mdc` (checked 25 Oct 2026).
const CURSOR_FRONTMATTER: &str = "\
---
description: \"PatchSense dependency security before adding or upgrading a package\"
alwaysApply: false
---
";

/// MCP snippets for Cursor, Claude Code, and Codex.
///
/// Checked 25 Oct 2026 against Cursor MCP docs, Claude Code MCP docs, and
/// Codex `config.toml`. This text is printed only. Nothing under the user
/// home directory is written.
pub const MCP_CONFIG: &str = r#"# Cursor: .cursor/mcp.json
{
  "mcpServers": {
    "patchsense": {
      "command": "patchsense",
      "args": ["mcp"]
    }
  }
}

# Claude Code
claude mcp add --transport stdio patchsense -- patchsense mcp

# Codex: ~/.codex/config.toml
[mcp_servers.patchsense]
command = "patchsense"
args = ["mcp"]
"#;

/// Which agent instruction files `init --agent` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTarget {
    /// `AGENTS.md`, `CLAUDE.md`, and the Cursor rule.
    All,
    /// `AGENTS.md` for Codex.
    Codex,
    /// `CLAUDE.md` for Claude Code.
    Claude,
    /// `.cursor/rules/patchsense.mdc`.
    Cursor,
}

impl AgentTarget {
    /// Parse `all`, `codex`, `claude`, or `cursor`.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "all" => Ok(Self::All),
            "codex" => Ok(Self::Codex),
            "claude" => Ok(Self::Claude),
            "cursor" => Ok(Self::Cursor),
            other => {
                anyhow::bail!("unknown agent `{other}`; expected all, codex, claude, or cursor")
            }
        }
    }
}

/// One instruction file written by `init --agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    /// Path relative to the directory that was passed in.
    pub relative: String,
    /// True when the file did not exist before this call.
    pub created: bool,
}

/// Write the idempotent instruction block for `target`.
pub fn write_agent_instructions(
    dir: &Path,
    target: AgentTarget,
) -> anyhow::Result<Vec<WrittenFile>> {
    let mut written = Vec::new();
    if matches!(target, AgentTarget::All | AgentTarget::Codex) {
        written.push(write_instruction(dir, "AGENTS.md", false)?);
    }
    if matches!(target, AgentTarget::All | AgentTarget::Claude) {
        written.push(write_instruction(dir, "CLAUDE.md", false)?);
    }
    if matches!(target, AgentTarget::All | AgentTarget::Cursor) {
        written.push(write_instruction(
            dir,
            ".cursor/rules/patchsense.mdc",
            true,
        )?);
    }
    Ok(written)
}

fn write_instruction(dir: &Path, relative: &str, cursor: bool) -> anyhow::Result<WrittenFile> {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let existed = path.is_file();
    let existing = if existed {
        std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };
    let next = if existing.trim().is_empty() {
        if cursor {
            format!("{CURSOR_FRONTMATTER}\n{INSTRUCTION_BLOCK}")
        } else {
            INSTRUCTION_BLOCK.to_string()
        }
    } else {
        upsert_block(&existing, relative)?
    };
    std::fs::write(&path, next).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(WrittenFile {
        relative: relative.to_string(),
        created: !existed,
    })
}

fn upsert_block(existing: &str, relative: &str) -> anyhow::Result<String> {
    let Some(start) = existing.find(START_MARKER) else {
        return Ok(append_block(existing));
    };
    let Some(rel_end) = existing[start..].find(END_MARKER) else {
        anyhow::bail!("{relative} has {START_MARKER} without {END_MARKER}");
    };
    let end = start + rel_end + END_MARKER.len();
    let mut out = String::new();
    out.push_str(&existing[..start]);
    out.push_str(INSTRUCTION_BLOCK.trim_end_matches('\n'));
    let rest = &existing[end..];
    if rest.is_empty() {
        out.push('\n');
    } else {
        out.push_str(rest);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

fn append_block(existing: &str) -> String {
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() && !out.ends_with("\n\n") {
        out.push('\n');
    }
    out.push_str(INSTRUCTION_BLOCK);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Write `patchsense.toml` in `dir`.
pub fn write_example_config(dir: &Path, force: bool) -> anyhow::Result<InitStatus> {
    let path = dir.join("patchsense.toml");
    if path.is_file() && !force {
        return Ok(InitStatus::Kept);
    }
    let replaced = path.is_file();
    std::fs::write(&path, EXAMPLE_CONFIG)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(if replaced {
        InitStatus::Replaced
    } else {
        InitStatus::Created
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_write_keeps_one_block_and_outside_text() {
        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(dir.path().join("AGENTS.md"), "# Project\n\nKeep this.\n").expect("seed");
        write_agent_instructions(dir.path(), AgentTarget::Codex).expect("first");
        let once = std::fs::read_to_string(dir.path().join("AGENTS.md")).expect("once");
        write_agent_instructions(dir.path(), AgentTarget::Codex).expect("second");
        let twice = std::fs::read_to_string(dir.path().join("AGENTS.md")).expect("twice");
        assert_eq!(once, twice);
        assert_eq!(twice.matches(START_MARKER).count(), 1);
        assert!(twice.contains("# Project"));
        assert!(twice.contains("Keep this."));
        assert!(!dir.path().join("CLAUDE.md").exists());
    }

    #[test]
    fn text_after_the_block_stays() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(&path, format!("BEFORE\n\n{INSTRUCTION_BLOCK}\nAFTER\n")).expect("seed");
        write_agent_instructions(dir.path(), AgentTarget::Claude).expect("first");
        let once = std::fs::read_to_string(&path).expect("once");
        write_agent_instructions(dir.path(), AgentTarget::Claude).expect("second");
        let twice = std::fs::read_to_string(&path).expect("twice");
        assert_eq!(once, twice);
        assert!(twice.starts_with("BEFORE\n"));
        assert!(twice.contains("\nAFTER\n"));
        assert_eq!(twice.matches(START_MARKER).count(), 1);
    }

    #[test]
    fn cursor_frontmatter_is_written_once() {
        let dir = tempfile::tempdir().expect("temp");
        write_agent_instructions(dir.path(), AgentTarget::Cursor).expect("first");
        write_agent_instructions(dir.path(), AgentTarget::Cursor).expect("second");
        let text =
            std::fs::read_to_string(dir.path().join(".cursor/rules/patchsense.mdc")).expect("rule");
        assert_eq!(text.matches("alwaysApply: false").count(), 1);
        assert_eq!(text.matches(START_MARKER).count(), 1);
        assert!(text.starts_with("---\n"));
    }

    #[test]
    fn unbalanced_marker_is_an_error() {
        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(
            dir.path().join("AGENTS.md"),
            "<!-- patchsense:start -->\nno end\n",
        )
        .expect("seed");
        let err = write_agent_instructions(dir.path(), AgentTarget::Codex).expect_err("unbalanced");
        assert!(err.to_string().contains("without"));
    }
}
