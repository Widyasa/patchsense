# PatchSense

`patchsense scan .` reads lockfiles, matches them to [OSV](https://osv.dev), and ranks each advisory with EPSS, CISA KEV, and CVSS. The table says which findings are **Critical**, which are **Review**, and which are **Defer**.

![Scan of log4j-core 2.14.1 showing CVE-2021-44228 as Critical](docs/demo.gif)

License: `MIT OR Apache-2.0` ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).

Repository: [github.com/Widyasa/patchsense](https://github.com/Widyasa/patchsense).

## Install

`0.1.0` is the crates.io release. Widya publishes it with `cargo publish` ([`docs/release-checklist.md`](docs/release-checklist.md)). There is no git tag and no GitHub Release for 0.1.0.

### Available for 0.1.0

```bash
cargo install patchsense --locked
```

That compiles from crates.io. It needs Rust 1.99 (`rust-version` in `Cargo.toml`).

From a git checkout, build the same binary without installing:

```bash
cargo build --release -p patchsense
cargo run -p patchsense -- --version
```

`cargo run -p patchsense -- --version` prints `patchsense 0.1.0`.

### Coming in v0.1.1

npm, pip, Composer, Go, Homebrew, the shell installer, and Docker are not part of 0.1.0. They need GitHub Release binaries, or a PyPI wheel, and those are planned for v0.1.1 after GitHub Actions billing is fixed. The commands below are kept so that release has a known shape. They do not work today.

| Channel | Command (coming in v0.1.1) | Notes |
|---|---|---|
| npm | `npm install --save-dev patchsense` then `npx patchsense scan .` | cargo-dist package. Also `pnpm add -D patchsense && pnpm exec patchsense scan .` and `yarn add -D patchsense && yarn patchsense scan .` |
| pip | `pip install patchsense` or `pipx install patchsense` or `uv tool install patchsense` | Wheels from `pypi.yml`: Linux x64/arm64 (manylinux, glibc), macOS x64/arm64, Windows x64. Not Alpine |
| Composer | `composer require --dev widyasa/patchsense` then `vendor/bin/patchsense scan .` | Root `composer.json`. First run downloads and checks sha256 |
| Go | `go install github.com/Widyasa/patchsense/go/cmd/patchsense@v0.1.0` | Same download and sha256 check. `@latest` tracks the newest tag. Before any tag, `@latest` is a pseudo-version and still looks for release `v0.1.0` |
| Homebrew | `brew install Widyasa/tap/patchsense` | Formula is pushed to `Widyasa/homebrew-tap` by the release workflow |
| shell | `curl --proto '=https' --tlsv1.2 -fsSL https://github.com/Widyasa/patchsense/releases/download/v0.1.0/patchsense-installer.sh \| sh` | cargo-dist installer. Checks sha256 before unpacking |
| Docker | `docker build -t patchsense .` then `docker run --rm -v "$PWD:/work" -w /work patchsense scan .` | Local image only. Alpine x64, so it uses the musl archive. The image is not pushed to a registry |

Those commands still name `v0.1.0` because that is the version recorded in the launchers. Phase B bumps the version to 0.1.1 and retargets the tag. Do not run them for the crates.io release.

cargo-dist archives for that later release cover:

| Triple | Where it runs |
|---|---|
| `x86_64-unknown-linux-gnu` | Linux x64, glibc |
| `x86_64-unknown-linux-musl` | Linux x64, musl (Alpine) |
| `aarch64-unknown-linux-gnu` | Linux arm64, glibc |
| `x86_64-apple-darwin` | macOS x64 |
| `aarch64-apple-darwin` | macOS arm64 |
| `x86_64-pc-windows-msvc` | Windows x64 |

There is no Linux arm64 musl archive and no Windows arm64 archive.

Composer, Go, and `scripts/fetch-release.sh` (the Docker entrypoint) cache the binary under `~/.cache/patchsense` (`PATCHSENSE_CACHE_DIR` overrides it). A later run does not need the network. `curl` and PHP's curl extension honor `https_proxy` / `http_proxy`. The Go launcher uses Go's default proxy rules, which skip loopback addresses. The cargo-dist npm installer stores the binary inside the installed package and does not check sha256. The shell installer, Homebrew formula, Composer, Go, and Docker entrypoint do.

`PATCHSENSE_TARGET` overrides target detection (`x86_64-unknown-linux-musl`, for example) when libc detection is wrong. It does not change the version.

`PATCHSENSE_BINARY` skips the download for Composer, Go, and the Docker entrypoint. Set it to a `patchsense` binary you already built. An empty value is ignored. Until the v0.1.1 GitHub Release exists, those three say release `v0.1.0` is not published yet and list `cargo install`, building from source (`cargo build --release -p patchsense`), and `PATCHSENSE_BINARY`. From a checkout:

```bash
cargo build --release -p patchsense
PATCHSENSE_BINARY=$PWD/target/release/patchsense go run ./go/cmd/patchsense --version
```

That prints `patchsense 0.1.0`.

`go install github.com/Widyasa/patchsense/go/cmd/patchsense@latest` before the first git tag installs a pseudo-version such as `v0.0.0-20261028141100-abcdefabcdef`. That names a commit, not a release. The launcher still requests GitHub Release `v0.1.0`, the version recorded in the source, and explains the pseudo-version when that release is missing. The 0.1.0 crates.io publish does not create that tag. `@latest` and `@v0.1.0` match a release only after Phase B tags v0.1.1 and bumps the version constant.

The pip wheel does not download a release, so it has no 404 path and does not read `PATCHSENSE_BINARY`. The npm package is generated by cargo-dist when the v0.1.1 release is published. It is not stored in this repository, and that generated installer does not read `PATCHSENSE_BINARY` either. Until v0.1.1, use `cargo install` or `PATCHSENSE_BINARY` with Composer, Go, or Docker.

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

Default tiers: **Critical** at 70 and above, **Review** at 40 and above, otherwise **Defer**. `--fail-on critical` is the default, so a Critical finding exits 1. Output is English only.

## GitHub Actions

The composite action's default path downloads a GitHub Release installer. That installer is coming in v0.1.1, not with the crates.io 0.1.0 publish. Until then, build the binary and pass `binary-path` (see [`.github/workflows/self-test.yml`](.github/workflows/self-test.yml)):

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

After v0.1.1 is released, the composite action installs the published binary. The `v0` tag is created then, not during the crates.io publish. That `uses:` line depends on the release:

```yaml
- uses: Widyasa/patchsense@v0
  with:
    path: .
    fail-on: critical
```

## GitLab CI

Copy [`templates/gitlab/patchsense.gitlab-ci.yml`](templates/gitlab/patchsense.gitlab-ci.yml) or include it. The installer URL in that template depends on a GitHub Release, which is coming in v0.1.1. A pipeline that reaches the install step fails until that release exists. Details: [`docs/gitlab.md`](docs/gitlab.md).

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

`patchsense scan . --explain` asks a local read-only agent (Codex, Claude Code, or Cursor) to explain the top findings. The text is labeled `AI explanation, may be wrong`. A missing agent, a timeout, or a bad response is a warning. It does not change the exit code. This command needs one of those CLIs on `PATH`.

MCP tools: `list_supported_lockfiles`, `scan_project`, `get_finding`, `get_fix_plan`, `explain_score`. `explain_score` is deterministic. It does not call an AI model.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished and `--fail-on` did not trip |
| 1 | A finding reached the `--fail-on` bar (`critical`, `review`, `any`, or a score) |
| 2 | The scan could not run: bad config, unreadable input, every lockfile failed, `--offline` is missing or past the OSV TTL, or `--strict-cache` found missing or expired EPSS or KEV. A launcher that cannot start the binary (missing `PATCHSENSE_BINARY`, unpublished release) also exits 2 |

`--fail-on never` stays 0 when findings exist. `--min-score` only hides rows. It does not change the exit code.

## Configuration

`patchsense init` writes the example. Flags override environment variables, which override the file. Useful variables: `PATCHSENSE_CONFIG`, `PATCHSENSE_CACHE_DIR`, `PATCHSENSE_FAIL_ON`, `PATCHSENSE_AGENT`, `PATCHSENSE_OSV_URL`, `PATCHSENSE_EPSS_URL`, `PATCHSENSE_KEV_URL`.

`patchsense cache info` and `patchsense cache clear` manage the SQLite cache (`~/.cache/patchsense/cache.db` on Linux). `--cache-dir` works before or after `info` and `clear`.

`--offline` reads OSV, EPSS, and KEV from that cache and does not call the network. Cache age follows `[cache] ttl_hours_osv`, `ttl_hours_epss`, and `ttl_hours_kev` (24 hours each when omitted). A missing OSV query or advisory exits 2. An expired one also exits 2, and the error names the age and the TTL. A missing EPSS row or KEV catalog is a warning, and that signal counts as absent. An expired EPSS or KEV row is still scored, with a warning that includes its age. The warning is printed on stderr, stored in the JSON report, and included in the Markdown report and in PR or MR comments. `--strict-cache` (or `strict_cache = true`) exits 2 when an EPSS row or the KEV catalog is missing or expired. When the setting comes from the file, the error says to set `[cache] strict_cache = false`. Run one online scan before using `--offline` in CI.

Supported lockfiles: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `requirements.txt`, `composer.lock`, `go.sum`, `pom.xml`, `Cargo.lock`. Requirements discovery also accepts `requirements-*.txt` (`requirements-dev.txt`), `requirements_*.txt` (`requirements_rag.txt`), `*.requirements.txt`, and any `.txt` file in a directory named `requirements`. The same paths work when passed explicitly. Matching ignores ASCII case. `-r`, `--requirement`, `-c`, and `--constraint` are read relative to the file that names them. A repeated name and version is kept once. A cycle or a missing include is a warning, not a failed scan. A remote include is skipped with a warning.

Go findings are version matches on the module in `go.sum`. When the advisory lists `affected[].ecosystem_specific.imports`, PatchSense also reads `.go` import blocks under the scan root. An exact path matches, and so does a subpackage (`golang.org/x/crypto/openpgp/packet` matches `golang.org/x/crypto/openpgp`). Aliases, dot imports, blank imports, and build-tag files count. `vendor/`, `testdata/`, and `*_test.go` are skipped unless `[scan.go_imports]` turns a skip off. If none of the listed paths are imported, the finding stays and gains the note `imported package not seen` in the table, JSON (`import_note`), SARIF, markdown, PR and MR comments, `--explain`, and MCP. The score and tier do not change: a missing import is not proof the package is unused. An advisory with no imports data is reported exactly as before. Details are in [`docs/go-import-reachability.md`](docs/go-import-reachability.md).

## Spec

The design source is [`docs/PRD.md`](docs/PRD.md). The task list is [`docs/TASKS.md`](docs/TASKS.md). Known gaps are [`docs/limitations.md`](docs/limitations.md). Agent rules are [`AGENTS.md`](AGENTS.md).

## Contributing

Contributions are licensed under `MIT OR Apache-2.0`, the same as the project. Fork the repository, branch from `master`, and open a pull request that says `Closes #N`. [CONTRIBUTING.md](CONTRIBUTING.md) covers the toolchain, the local checks, and how to add a lockfile parser or a report format.
