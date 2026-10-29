# PatchSense

[![crates.io](https://img.shields.io/crates/v/patchsense.svg)](https://crates.io/crates/patchsense)
[![license](https://img.shields.io/crates/l/patchsense.svg)](https://github.com/Widyasa/patchsense#license)

PatchSense reads your lockfiles, looks up every pinned package in [OSV](https://osv.dev), and ranks each advisory from 0 to 100 using CISA KEV (known exploited), FIRST EPSS (exploit probability), CVSS, whether the package is a direct dependency, and whether a fix exists. Instead of a flat list of CVEs you get three tiers, **Critical**, **Review**, and **Defer**, so you know what to patch first. It runs locally, caches data in SQLite, works offline from that cache, writes table, JSON, SARIF, Markdown, and GitLab reports, can post a pull-request or merge-request comment, and ships an MCP server for coding agents.

![Scan of log4j-core 2.14.1 showing CVE-2021-44228 as Critical](https://raw.githubusercontent.com/Widyasa/patchsense/master/docs/demo.gif)

## Install

### cargo (available now)

```bash
cargo install patchsense --locked
```

This installs the latest `patchsense` release from crates.io. It needs Rust 1.99 or newer (`rust-version` in `Cargo.toml`).

From a checkout of this repository:

```bash
cargo build --release -p patchsense
cargo run -p patchsense -- --version
```

### Prebuilt binaries

npm, PyPI, Composer, Go, Homebrew, the shell installer, and Docker install a prebuilt binary from GitHub Release [`v0.1.2`](https://github.com/Widyasa/patchsense/releases/tag/v0.1.2). The npm, PyPI, and Composer commands work once the package is live on that registry.

| Channel | Command | Notes |
|---|---|---|
| npm | `npm install --save-dev patchsense`, then `npx patchsense scan .` | cargo-dist package, created when the GitHub Release is published. Also `pnpm add -D patchsense && pnpm exec patchsense scan .` and `yarn add -D patchsense && yarn patchsense scan .` |
| PyPI | `pip install patchsense`, `pipx install patchsense`, or `uv tool install patchsense` | Wheels from [`.github/workflows/pypi.yml`](.github/workflows/pypi.yml): Linux x64 and arm64 (manylinux, glibc), macOS x64 and arm64, Windows x64. Not Alpine. The wheel does not download a GitHub Release |
| Composer | `composer require --dev widyasa/patchsense`, then `vendor/bin/patchsense scan .` | Root [`composer.json`](composer.json). The first run downloads the release archive and checks sha256 |
| Go | `go install github.com/Widyasa/patchsense/go/cmd/patchsense@v0.1.2` | [`go/cmd/patchsense`](go/cmd/patchsense) downloads the same archive and checks sha256 |
| Homebrew | `brew install Widyasa/tap/patchsense` | Formula in [`Widyasa/homebrew-tap`](https://github.com/Widyasa/homebrew-tap) |
| shell | `curl --proto '=https' --tlsv1.2 -fsSL https://github.com/Widyasa/patchsense/releases/download/v0.1.2/patchsense-installer.sh \| sh` | cargo-dist installer. Checks sha256 before unpacking. Windows: `patchsense-installer.ps1` |
| Docker | `docker build -t patchsense .`, then `docker run --rm -v "$PWD:/work" -w /work patchsense scan .` | Local image only ([`Dockerfile`](Dockerfile)). Alpine x64, so [`scripts/fetch-release.sh`](scripts/fetch-release.sh) downloads the musl archive. The image is not pushed to a registry |

The release archives cover `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`. There is no Linux arm64 musl archive and no Windows arm64 archive.

Composer, Go, and the Docker entrypoint cache the downloaded binary under `~/.cache/patchsense` (`PATCHSENSE_CACHE_DIR` overrides that directory). `PATCHSENSE_BINARY` points them at a binary you already built and skips the download. `PATCHSENSE_TARGET` overrides target detection. The PyPI wheel and the cargo-dist npm package do not read `PATCHSENSE_BINARY`.

Archives are `patchsense-<target>.tar.gz` (Windows included) and are listed with their sha256 in the release `dist-manifest.json` and `sha256.sum`.

## Quick start

```bash
patchsense scan .                         # scan every lockfile under the current directory
patchsense scan . --fail-on review        # exit 1 if any finding is Review or Critical
patchsense scan . -f json -o report.json  # save a JSON report
patchsense init                           # write an example patchsense.toml
patchsense scan . --offline               # rescan from the local cache, no network
```

Example output:

```text
┌───────┬──────────┬─────────────────────────────────────┬─────────┬──────────────────────────────────────┬─────┬────────────────────────────┬──────┬────────┐
│ Score ┆ Tier     ┆ Package                             ┆ Version ┆ Advisory/CVE                         ┆ KEV ┆ EPSS                       ┆ CVSS ┆ Fix    │
╞═══════╪══════════╪═════════════════════════════════════╪═════════╪══════════════════════════════════════╪═════╪════════════════════════════╪══════╪════════╡
│ 100   ┆ Critical ┆ org.apache.logging.log4j:log4j-core ┆ 2.14.1  ┆ GHSA-jfh8-c2jp-5v3q (CVE-2021-44228) ┆ yes ┆ 1.0000 (percentile 1.0000) ┆ 10   ┆ 2.15.0 │
│ 62    ┆ Review   ┆ org.apache.logging.log4j:log4j-core ┆ 2.14.1  ┆ GHSA-p6xc-xr62-6r2g (CVE-2021-45105) ┆ no  ┆ 1.0000 (percentile 0.9999) ┆ 8.6  ┆ 2.17.0 │
│ 34    ┆ Defer    ┆ org.apache.logging.log4j:log4j-core ┆ 2.14.1  ┆ GHSA-6hg6-v5c8-fphq (CVE-2026-34477) ┆ no  ┆ 0.0056 (percentile 0.4647) ┆ 6.3  ┆ 2.25.4 │
└───────┴──────────┴─────────────────────────────────────┴─────────┴──────────────────────────────────────┴─────┴────────────────────────────┴──────┴────────┘
Critical: 2  Review: 2  Defer: 4
```

## Command reference

```text
patchsense <COMMAND>

  scan     Scan lockfiles and print matching advisories
  cache    Inspect or delete the local SQLite cache
  init     Write an example config, agent instructions, or MCP snippets
  comment  Create or update a pull-request comment from a JSON report
  mcp      Run the MCP server on stdio
  help     Print help for a subcommand

  -h, --help     Print help
  -V, --version  Print version
```

### `patchsense scan [OPTIONS] [PATH]`

`PATH` is a directory or a single lockfile. Default: the current directory.

| Option | Description |
|---|---|
| `--ecosystem <LIST>` | Ecosystems to scan, comma-separated (`npm,pypi`). Repeatable. Names: `npm`, `pypi`, `packagist` (or `composer`), `go`, `maven`, `cargo` (or `crates.io`). |
| `--no-dev` | Skip packages the parser marked as dev dependencies. |
| `--exclude <GLOB>` | Extra paths to skip. Repeatable. Added to `[scan] exclude`. |
| `--keep-going` | Continue after a lockfile fails to parse. This is the default. |
| `--no-keep-going` | Stop at the first lockfile that cannot be read or parsed. |
| `--fail-on <WHEN>` | Exit 1 when a finding reaches this bar: `critical` (default), `review`, `any`, `never`, or a score `0`–`100`. |
| `--min-score <N>` | Hide findings below this score in every output. Does not change the exit code. |
| `-f, --format <FORMAT>` | `table`, `json`, `sarif`, `markdown`, or `gitlab`. Repeatable, paired with `--output` in order. |
| `-o, --output <FILE>` | Write the paired `--format` to this file instead of stdout. Repeatable. Parent directories are created. |
| `--no-color` | Plain table. `NO_COLOR` is also honored. |
| `--offline` | Use only the local cache. No network calls. |
| `--strict-cache` | With `--offline`, exit 2 when an EPSS row or the KEV catalog is missing or past its TTL. |
| `--no-cache` | Do not read or write the cache. |
| `--cache-dir <DIR>` | Directory containing `cache.db`. Overrides `PATCHSENSE_CACHE_DIR`. |
| `--config <FILE>` | Path to `patchsense.toml`. Overrides discovery and `PATCHSENSE_CONFIG`. |
| `--explain` | Ask a local coding agent CLI to explain the top findings. |
| `--agent <AGENT>` | Agent for `--explain`: `auto`, `codex`, `claude`, or `cursor`. |
| `--explain-top <N>` | Number of findings sent to the agent. Default from `[explain] top` (10). |

Writing several reports in one run:

```bash
patchsense scan . --no-color \
  --format json     --output patchsense-report.json \
  --format sarif    --output patchsense.sarif \
  --format markdown --output patchsense-report.md
```

Rules for pairing: the n-th `--format` goes to the n-th `--output`. At most one format may be left without an `--output` (it goes to stdout). More `--output` values than `--format` values is an error.

### `patchsense cache [--cache-dir <DIR>] <info|clear>`

| Command | Description |
|---|---|
| `cache info` | Print the cache path, schema version, and row counts (`osv_vuln`, `osv_query`, `epss`, `kev`). |
| `cache clear` | Delete `cache.db`. |

`--cache-dir` works before or after the subcommand (`cache info --cache-dir DIR` or `cache --cache-dir DIR info`).

### `patchsense init [OPTIONS]`

| Option | Description |
|---|---|
| *(none)* | Write an example `patchsense.toml` in the current directory. An existing file is kept. |
| `--force` | Replace an existing `patchsense.toml`. |
| `--agent [<AGENT>]` | Also write a PatchSense instruction block for `all` (default when no value), `codex` (`AGENTS.md`), `claude` (`CLAUDE.md`), or `cursor` (`.cursor/rules/patchsense.mdc`). The block sits between `<!-- patchsense:start -->` and `<!-- patchsense:end -->` and is updated in place on rerun. |
| `--print-mcp-config` | Print MCP config snippets for Cursor, Claude Code, and Codex. Writes no files and no `patchsense.toml`. |

### `patchsense comment --report <FILE> [OPTIONS]`

Posts the Markdown summary of a JSON report as a pull-request comment (GitHub) or merge-request note (GitLab). A hidden `<!-- patchsense-report -->` marker means later runs edit the same comment instead of adding a new one.

| Option | Description |
|---|---|
| `--report <FILE>` | JSON report from `patchsense scan --format json`. Required. |
| `--provider <PROVIDER>` | `auto` (default), `github`, or `gitlab`. `auto` picks GitHub when `GITHUB_ACTIONS=true`, GitLab when `GITLAB_CI=true`. |
| `--top <N>` | Findings in the comment table. Default 20. |
| `--dry-run` | Print the Markdown and do not call any API. |

Environment it reads:

- GitHub: `GITHUB_TOKEN` with `pull-requests: write`, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, optional `GITHUB_API_URL`. The comment is a pull-request conversation comment: `GET` and `POST /repos/{owner}/{repo}/issues/{pull_number}/comments`, and `PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}`. On a pull request, `pull-requests: write` authorizes those calls. `issues: write` is not required.
- GitLab: `GITLAB_TOKEN` (project access token with `api` scope; `CI_JOB_TOKEN` cannot write notes), `CI_API_V4_URL`, `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`.

### `patchsense mcp`

Runs a Model Context Protocol server on stdio. Tools:

| Tool | Parameters | Returns |
|---|---|---|
| `list_supported_lockfiles` | none | Lockfile names and their OSV ecosystems |
| `scan_project` | `path`, `ecosystems`, `min_score`, `include_dev`, `offline` | Top 50 findings plus the full summary |
| `get_finding` | `id` (GHSA, CVE, or OSV id), `path` | One advisory |
| `get_fix_plan` | `path`, `tier` (`critical`, `review`, `defer`) | Minimum upgrade covering every advisory on a package |
| `explain_score` | `id`, `path` | Deterministic score breakdown (no AI call) |

`patchsense init --print-mcp-config` prints ready-to-paste snippets, for example Cursor's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "patchsense": { "command": "patchsense", "args": ["mcp"] }
  }
}
```

Claude Code: `claude mcp add --transport stdio patchsense -- patchsense mcp`

## How the score works

Each finding gets 0–100 points:

| Signal | Default weight | Meaning |
|---|---:|---|
| KEV | 35 | CVE is in the CISA Known Exploited Vulnerabilities catalog |
| EPSS | 25 | FIRST exploit probability; full weight at probability 0.10 (`probability` mode) |
| CVSS | 20 | Highest usable CVSS base score / 10 |
| Direct | 10 | Package is a direct dependency |
| Fix available | 10 | OSV lists a fixed version |

Tiers: **Critical** ≥ 70, **Review** ≥ 40, otherwise **Defer**. Weights that do not sum to 100 are scaled to 100, with a warning. All of this is configurable.

## Configuration

PatchSense looks for `patchsense.toml` starting at the scan directory and walking up to the git root. `--config` or `PATCHSENSE_CONFIG` points at a specific file. Precedence: **flag > environment variable > file > built-in default**. Unknown keys are rejected. Every key is optional; this is the full file with defaults:

```toml
schema_version = 1                      # only 1 is accepted

[scan]
ecosystems = ["npm", "pypi", "packagist", "go", "maven", "cargo"]  # default: all
exclude = []                            # extra glob patterns to skip
include_dev = true                      # false = same as --no-dev
fail_on = "critical"                    # critical | review | any | never | 0-100

[scan.go_imports]                       # Go import check, see below
skip_vendor = true                      # skip directories named vendor
skip_testdata = true                    # skip directories named testdata
skip_tests = true                       # skip *_test.go

[score.weights]
kev = 35
epss = 25
cvss = 20
direct = 10
fix_available = 10

[score.epss]
mode = "probability"                    # probability | percentile
saturation = 0.10                       # probability that earns the full EPSS weight

[score.thresholds]
critical = 70
review = 40

[score.unknown_direct]
weight_fraction = 1.0                   # share of the direct weight when the parser cannot tell

[cache]
ttl_hours_osv = 24                      # whole hours
ttl_hours_epss = 24
ttl_hours_kev = 24
strict_cache = false                    # true = --strict-cache

[output]
top = 20                                # rows in the Markdown report

[explain]
agent = "auto"                          # auto | codex | claude | cursor
top = 10                                # findings sent to the agent
timeout_secs = 120

# Suppress an advisory. Repeat the table for more rules.
[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"              # OSV, GHSA, or CVE id (aliases match too)
reason = "Used only in a build script"  # required
expires = "2027-01-31"                  # optional, inclusive YYYY-MM-DD
```

Ignored findings are listed under `ignored` in the JSON report. An expired rule is dropped with a warning. `[explain] lang` from older configs is accepted but ignored (output is English only).

### Environment variables

| Variable | Effect |
|---|---|
| `PATCHSENSE_CONFIG` | Config file path (overridden by `--config`) |
| `PATCHSENSE_CACHE_DIR` | Cache directory (overridden by `--cache-dir`) |
| `PATCHSENSE_FAIL_ON` | Same values as `--fail-on` |
| `PATCHSENSE_AGENT` | Same values as `--agent` |
| `PATCHSENSE_OSV_URL` | OSV API base URL (default `https://api.osv.dev`) |
| `PATCHSENSE_EPSS_URL` | EPSS API base URL (default `https://api.first.org`) |
| `PATCHSENSE_KEV_URL` | Full URL of the CISA KEV JSON feed |
| `NO_COLOR` | Disable table colors |

## Output formats

| Format | Use |
|---|---|
| `table` | Human-readable priority table. Default when stdout is a terminal. |
| `json` | Full report (`schema_version`, `tool`, `target`, `lockfiles`, `data_sources`, `summary`, `findings`, `ignored`, `warnings`, …). Default when stdout is a pipe or file. Schema: [`schemas/report.v1.json`](schemas/report.v1.json). |
| `sarif` | SARIF 2.1.0 for GitHub code scanning and other SARIF viewers. |
| `markdown` | Summary and findings table with per-finding details. This is the PR/MR comment body. |
| `gitlab` | GitLab Dependency Scanning report (schema 15.2.5). |

Warnings (stale cache, parse failures, unsupported lockfiles) go to stderr and are also stored in the JSON and Markdown reports.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished and no finding reached the `--fail-on` bar |
| `1` | At least one finding reached the `--fail-on` bar |
| `2` | The scan could not run: bad config or flag value, no supported lockfile, unreadable input, every lockfile failed, offline OSV cache missing or expired, `--strict-cache` with missing or expired EPSS/KEV, or a `comment` API error |

`--fail-on never` always exits 0 when the scan runs. `--min-score` never changes the exit code.

## Offline mode and cache

Data is cached in `cache.db`:

| OS | Default location |
|---|---|
| Linux | `$XDG_CACHE_HOME/patchsense/` or `~/.cache/patchsense/` |
| macOS | `~/Library/Caches/patchsense/` (or `$XDG_CACHE_HOME/patchsense/` if set) |
| Windows | `%LOCALAPPDATA%\patchsense\` (or `$XDG_CACHE_HOME/patchsense/` if set) |

Online scans reuse rows younger than their TTL and refetch older ones. With `--offline`:

- **OSV** results must be in the cache and within `ttl_hours_osv`. A missing or expired row exits 2 and the error says which package and how old. No partial report is printed.
- **EPSS / KEV**: a missing row is a warning and that signal counts as absent. An expired row is still used, with a warning naming its age, so scores do not drop just because the cache aged.
- `--strict-cache` (or `[cache] strict_cache = true`) turns missing or expired EPSS/KEV into exit 2.

Typical CI pattern: run one online scan to warm the cache, then `--offline` for later runs.

```bash
patchsense scan .             # fills the cache
patchsense scan . --offline   # reuses it
patchsense cache info         # see what is stored
```

## CI usage

Any CI that has Rust:

```bash
cargo install patchsense --locked
patchsense scan . --no-color --fail-on critical \
  --format json  --output patchsense-report.json \
  --format sarif --output patchsense.sarif
```

GitHub Actions with a PR comment:

```yaml
permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install patchsense --locked
      - run: patchsense scan . --no-color --format json --output patchsense-report.json
      - if: always() && github.event_name == 'pull_request'
        run: patchsense comment --report patchsense-report.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`pull-requests: write` is the permission for that comment. `patchsense comment` writes a pull-request conversation comment through the issue-comment routes above, and GitHub authorizes those routes on a pull request with `pull-requests: write`. `issues: write` is not required.

The composite action in [`action.yml`](action.yml) downloads the GitHub Release installer by default (`uses: Widyasa/patchsense@v0`, or pin `version: 0.1.2`). To test an unreleased build instead, build the binary and pass `binary-path`, as [`.github/workflows/self-test.yml`](.github/workflows/self-test.yml) does. The job needs `pull-requests: write` when `comment` is left at its default (`true`), and `security-events: write` when `sarif` is left at its default (`true`):

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  patchsense:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release -p patchsense --bin patchsense
      - uses: ./
        with:
          path: .
          fail-on: critical
          binary-path: target/release/patchsense
```

On GitLab, run the same scan with `--format gitlab --output gl-dependency-scanning-report.json` and `patchsense comment --provider gitlab` with a masked `GITLAB_TOKEN`. [`templates/gitlab/patchsense.gitlab-ci.yml`](templates/gitlab/patchsense.gitlab-ci.yml) is the template. Its installer downloads `patchsense-installer.sh` from the GitHub Release (`latest`, or set `PATCHSENSE_VERSION`). Details are in [`docs/gitlab.md`](docs/gitlab.md).

## Supported ecosystems and lockfiles

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| PyPI | `poetry.lock`, `requirements.txt` |
| Packagist (PHP) | `composer.lock` |
| Go | `go.sum` |
| Maven | `pom.xml` |
| crates.io | `Cargo.lock` |

Details:

- Directories named `node_modules`, `vendor`, `target`, `.git`, `.venv`, and `venv` are skipped during discovery.
- **requirements**: discovery also picks up `requirements-*.txt`, `requirements_*.txt`, `*.requirements.txt`, and any `.txt` inside a `requirements/` directory (case-insensitive). `-r`/`--requirement` and `-c`/`--constraint` includes are followed relative to the including file. A cycle or missing include is a warning; remote includes are skipped with a warning.
- **Composer**: `platform` constraints such as `php: ^8.3` are skipped; a concrete version such as `php: 8.3.35` is scanned.
- **Go import check**: when an OSV advisory lists affected import paths, PatchSense checks `.go` files under the scan root. If none of those packages is imported, the finding stays (same score and tier) but gets the note `imported package not seen` (JSON field `import_note`). Subpackages, aliases, dot, and blank imports count. See [`docs/go-import-reachability.md`](docs/go-import-reachability.md).
- **Not supported**: `bun.lock` / `bun.lockb` (a warning is printed when one is found).

## `--explain` (optional AI summary)

`patchsense scan . --explain` sends the top findings to a local, read-only coding agent CLI found on `PATH`: `codex`, `claude`, or Cursor's `agent` / `cursor-agent`. With `auto` they are tried in that order. The text is labeled `AI explanation, may be wrong`. A missing agent, a timeout (`[explain] timeout_secs`), or a bad response is only a warning and never changes the exit code.

## Troubleshooting / FAQ

**`error: no supported lockfile found in .`** — Run from the project root, pass the lockfile path directly, or check that the file is not under a skipped directory or `--exclude` / `[scan] exclude`.

**`error: offline cache is missing OSV results …`** — Run one scan without `--offline` first, using the same `--cache-dir` (or `PATCHSENSE_CACHE_DIR`). `--offline` together with `--no-cache` can never succeed.

**`offline cache expired …`** — Rerun online, or raise `[cache] ttl_hours_osv`.

**`more than one --format would be written to stdout`** — Give every `--format` except one an `--output`.

**`failed to parse fail_on`** — Use `critical`, `review`, `any`, `never`, or an integer `0`–`100`.

**`unknown field` in the config** — Keys are strict; compare with the configuration reference above.

**`could not detect a comment provider`** — Outside GitHub Actions or GitLab CI, pass `--provider github` or `--provider gitlab`, or use `--dry-run` to preview.

**A Go finding says `imported package not seen`.** — Your code does not import the vulnerable package of that module. The finding is kept because tests, vendored code, and build tags are not fully analysed; verify before ignoring it with an `[[ignore]]` rule.

**Is my code uploaded anywhere?** — No. Only package names and versions are sent to OSV, and CVE ids to EPSS; the KEV catalog is downloaded as a whole. `--offline` makes no network calls.

## Links

- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
- Known limitations: [`docs/limitations.md`](docs/limitations.md)
- Go import check: [`docs/go-import-reachability.md`](docs/go-import-reachability.md)
- GitLab CI: [`docs/gitlab.md`](docs/gitlab.md)
- Release checklist: [`docs/release-checklist.md`](docs/release-checklist.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- JSON schema: [`schemas/report.v1.json`](schemas/report.v1.json)
- Issues: <https://github.com/Widyasa/patchsense/issues>
- Library API docs: <https://docs.rs/patchsense>

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
