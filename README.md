# PatchSense

CVE triage CLI: prioritize vulnerabilities from lockfiles using OSV, EPSS, and CISA KEV.

`patchsense scan .` reports which CVEs are **Kritis**, which are **Perlu dicek**, and which **Bisa ditunda**, with the reason and a fixed version. License: `MIT OR Apache-2.0`.

Repository: [github.com/Widyasa/patchsense](https://github.com/Widyasa/patchsense).

## Spec package

This repository is built from the PatchSense handoff. The design source of truth is the page "PatchSense: Rancangan Produk" v1. If this spec disagrees with that page, the page wins.

| File | Purpose |
|---|---|
| [`docs/PRD.md`](docs/PRD.md) | Product spec: problem, users, goals and non-goals, MVP features and acceptance criteria, CLI and exit codes, `patchsense.toml`, JSON schema, score formula, crate architecture, MCP, agent adapters, GitHub Action, GitLab CI, distribution, risks, and open decisions |
| [`docs/TASKS.md`](docs/TASKS.md) | 54 ordered tasks across 6 weeks (W1-T1 through W6-T7), each with a description, files, done criteria, and dependencies |
| [`AGENTS.md`](AGENTS.md) | Working rules for coding agents: Rust conventions, test rules (no network, real fixtures, `insta` snapshots), per-task workflow, and definition of done |
| [`CLAUDE.md`](CLAUDE.md) | Points Claude Code at `AGENTS.md` |

## How agents should work

1. Read [`AGENTS.md`](AGENTS.md), [`docs/PRD.md`](docs/PRD.md), and [`docs/TASKS.md`](docs/TASKS.md).
2. Take the next unchecked task (starting at W1-T1). One task, one branch, one pull request. Follow the definition of done, including the Git flow at the bottom of `AGENTS.md`: open an issue first, then a PR that says `Closes #<n>`, and merge to `master` only when CI is green.
3. The package name is final: `patchsense` on npm, PyPI, crates.io, and Homebrew. The GitHub owner is `Widyasa`.
4. Review the PR, merge it to `master`, then repeat from the updated `master`. Week 2 parsers (W2-T1 through W2-T7) can be split across agents.
5. Steps that need accounts and secrets (pushing tags, publishing to npm, PyPI, crates.io, or Homebrew, and a live GitLab trial) are done by Widya. Agents only prepare the commands and the checklist.

## Notes

- The API endpoints in the PRD (OSV querybatch and vulns, FIRST EPSS, CISA KEV JSON) were checked on 25 October 2026.
- Crate versions are intentionally not pinned in the spec. Add dependencies with `cargo add` (latest stable) and commit `Cargo.lock`.
- CLI flags for Codex, Claude Code, and Cursor were checked against official docs on 25 October 2026 and can change. Re-check them when doing W5-T8.

## Build

```bash
cargo build --workspace
cargo run -p patchsense -- --version
```

The workspace is `crates/patchsense-core` (library) and `crates/patchsense` (binary). Edition 2021. Minimum Rust version is recorded in `rust-version` (`Cargo.toml`).
