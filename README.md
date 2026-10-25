# PatchSense

`patchsense scan .` reads lockfiles, matches them to [OSV](https://osv.dev), and ranks each advisory with EPSS, CISA KEV, and CVSS. The table says which findings are **Kritis**, which are **Perlu dicek**, and which **Bisa ditunda**.

![Scan of log4j-core 2.14.1 showing CVE-2021-44228 as Kritis](docs/demo.gif)

License: `MIT OR Apache-2.0` ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).

Repository: [github.com/Widyasa/patchsense](https://github.com/Widyasa/patchsense).

## Install

Four release channels are prepared. The publish steps themselves are for Widya ([`docs/release-checklist.md`](docs/release-checklist.md)). Until `v0.1.0` is tagged, build from source.

| Channel | After the v0.1.0 release | Works today |
|---|---|---|
| cargo | `cargo install patchsense --locked` | `cargo install --path crates/patchsense --locked` |
| npm | `npx patchsense scan .` | Needs the GitHub Release from cargo-dist |
| pip | `pip install patchsense` | `maturin build --release` then `pip install` the wheel |
| Homebrew | `brew install Widyasa/tap/patchsense` | Needs the `Widyasa/homebrew-tap` formula |

From a git checkout:

```bash
cargo run -p patchsense -- --version
```

That prints `patchsense 0.1.0`.

## Quick start

```bash
patchsense init
patchsense scan .
```

`init` writes `patchsense.toml` and does not replace an existing file unless you pass `--force`. A TTY prints a table. A pipe prints JSON. Write every report in one pass:

```bash
patchsense scan . --no-color \
  --format json --output patchsense-report.json \
  --format sarif --output patchsense.sarif \
  --format markdown --output patchsense-report.md
```

The demo GIF scans [`examples/kev-log4shell`](examples/kev-log4shell), which pins `log4j-core` 2.14.1 (CVE-2021-44228, CISA KEV). [`examples/php2shell-demo`](examples/php2shell-demo) pins PHP 8.3.35. On 25 Oct 2026 OSV returned no advisory for that Packagist `php` package, so the GIF uses Log4Shell.

## How the score works

Each finding is 0–100. Default weights sum to 100. A weight set that does not sum to 100 is scaled and a warning is printed.

| Signal | Default weight | What it measures |
|---|---:|---|
| KEV | 35 | CVE is in the CISA Known Exploited Vulnerabilities catalog |
| EPSS | 25 | FIRST exploit probability, saturated at 0.10 in `probability` mode |
| CVSS | 20 | Highest usable CVSS base score, divided by 10 |
| Direct | 10 | The package is a direct dependency |
| Fix available | 10 | OSV lists a fixed version |

Default tiers: **Kritis** at 70 and above, **Perlu dicek** at 40 and above, otherwise **Bisa ditunda**. `--fail-on critical` is the default, so a Kritis finding exits 1.

## GitHub Actions

Before a release, build the binary and pass `binary-path` (see [`.github/workflows/self-test.yml`](.github/workflows/self-test.yml)):

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo build --release -p patchsense --bin patchsense
- uses: ./
  with:
    path: .
    fail-on: critical
    binary-path: target/release/patchsense
```

After `v0.1.0` is released, the composite action installs the published binary. That `uses:` line depends on the release:

```yaml
- uses: Widyasa/patchsense@v0
  with:
    path: .
    fail-on: critical
```

## GitLab CI

Copy [`templates/gitlab/patchsense.gitlab-ci.yml`](templates/gitlab/patchsense.gitlab-ci.yml) or include it. The installer URL in that template depends on a GitHub Release. Details: [`docs/gitlab.md`](docs/gitlab.md).

```yaml
include:
  - local: templates/gitlab/patchsense.gitlab-ci.yml

variables:
  PATCHSENSE_FAIL_ON: critical
```

Set a masked `GITLAB_TOKEN` (project access token, `api` scope) when the job should comment on the merge request.

## MCP and `--explain`

```bash
patchsense mcp
patchsense init --print-mcp-config
patchsense init --agent
```

`--print-mcp-config` prints snippets for Cursor (`.cursor/mcp.json`), Claude Code, and Codex. It does not write those files. `--agent` writes an instruction block between `<!-- patchsense:start -->` and `<!-- patchsense:end -->` in `AGENTS.md`, `CLAUDE.md`, and `.cursor/rules/patchsense.mdc`.

`patchsense scan . --explain` asks a local read-only agent (Codex, Claude Code, or Cursor) to explain the top findings. The text is labeled `Penjelasan AI, bisa keliru`. A missing agent, a timeout, or a bad response is a warning. It does not change the exit code. This command needs one of those CLIs on `PATH`.

MCP tools: `list_supported_lockfiles`, `scan_project`, `get_finding`, `get_fix_plan`, `explain_score`. `explain_score` is deterministic. It does not call an AI model.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished and `--fail-on` did not trip |
| 1 | A finding reached the `--fail-on` bar (`critical`, `review`, `any`, or a score) |
| 2 | The scan could not run: bad config, unreadable input, or every lockfile failed |

`--fail-on never` stays 0 when findings exist. `--min-score` only hides rows. It does not change the exit code.

## Configuration

`patchsense init` writes the example. Flags override environment variables, which override the file. Useful variables: `PATCHSENSE_CONFIG`, `PATCHSENSE_CACHE_DIR`, `PATCHSENSE_FAIL_ON`, `PATCHSENSE_AGENT`, `PATCHSENSE_OSV_URL`, `PATCHSENSE_EPSS_URL`, `PATCHSENSE_KEV_URL`.

`patchsense cache info` and `patchsense cache clear` manage the SQLite cache (`~/.cache/patchsense/cache.db` on Linux).

Supported lockfiles: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `requirements.txt`, `composer.lock`, `go.sum`, `pom.xml`, `Cargo.lock`.

## Spec

The design source is [`docs/PRD.md`](docs/PRD.md). The task list is [`docs/TASKS.md`](docs/TASKS.md). Agent rules are [`AGENTS.md`](AGENTS.md).
