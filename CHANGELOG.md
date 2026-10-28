# Changelog

All notable changes to PatchSense are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased / 0.1.1 (planned)

Binary channels, after GitHub Actions billing is fixed. The crates.io 0.1.0 publish does not create a git tag. `v0.1.0` and `v0` are created with v0.1.1, not before.

- GitHub Release binaries via cargo-dist (Linux x64 glibc and musl, Linux arm64 glibc, macOS x64 and arm64, Windows x64).
- npm installer from cargo-dist.
- PyPI wheels from `pypi.yml`.
- Packagist package `widyasa/patchsense`, plus the Packagist GitHub webhook.
- Go launcher `github.com/Widyasa/patchsense/go/cmd/patchsense` at the release tag.
- Homebrew formula pushed to `Widyasa/homebrew-tap`.
- Shell installer from the GitHub Release.
- Docker entrypoint that downloads the musl archive. The image stays local; it is not pushed.
- Version bump to 0.1.1, then `cargo publish` of `patchsense-core` and `patchsense` so `cargo install` matches the binaries.

## [0.1.0] - YYYY-MM-DD

Replace `YYYY-MM-DD` with the day `cargo publish` runs. See [`docs/release-checklist.md`](docs/release-checklist.md). This release is crates.io only: `patchsense-core`, then `patchsense`. It does not push a tag and it does not publish npm, PyPI, Packagist, Go, Homebrew, Docker, or the shell installer.

### Added

- Lockfile parsers for npm, pnpm, Yarn, Poetry, `requirements.txt`, Composer, Go, Maven, and Cargo.
- Requirements discovery accepts `requirements-*.txt`, `requirements_*.txt`, `requirements.*.txt`, `*.requirements.txt`, and `requirements/*.txt`, including when one of those paths is passed explicitly (#125, #126).
- Requirements files follow `-r` and `-c` includes relative to the including file. Cycles and duplicate pins collapse. A missing include is a warning (#127, #128).
- OSV matching with EPSS, CISA KEV, and CVSS, plus a 0–100 priority score.
- Table, JSON, SARIF, markdown, and GitLab Dependency Scanning reports.
- `patchsense comment` for GitHub pull requests and GitLab merge requests.
- `patchsense mcp` tools and `patchsense scan --explain` for a local read-only agent.
- `patchsense init`, including `--agent` and `--print-mcp-config`.
- Go findings keep `affected[].ecosystem_specific.imports` (`path` and `symbols`). When those paths are present and none of them are imported from the project's `.go` files, the finding stays and carries the note `imported package not seen`. The score and tier do not change. Advisories with no imports data are unchanged. `vendor/`, `testdata/`, and `*_test.go` are skipped by default (`[scan.go_imports]`).
- GitHub composite action, GitLab CI template, cargo-dist installer config, and a maturin wheel config. The binaries those configs download are published in 0.1.1, not in this release.
- Composer package layout `widyasa/patchsense` and Go launcher `github.com/Widyasa/patchsense/go/cmd/patchsense`. Both download a GitHub Release binary. That download is a 0.1.1 channel.
- Docker entrypoint `scripts/fetch-release.sh`. `docker build` stays local; the image is not pushed.

### Fixed

- `[cache] ttl_hours_osv`, `ttl_hours_epss`, and `ttl_hours_kev` set the cache lifetime. The default is still 24 hours. A value that is not a whole number of hours is a config error that names the key (#137).
- `--offline` keeps using an expired EPSS row or KEV catalog and warns with its age, so the score does not drop. `--strict-cache` and `[cache] strict_cache` exit 2 when one of those rows is expired (#137).
- EPSS probability and percentile are shown to four decimal places in the table, markdown, and `explain_score` (#137).
- `--offline` loads EPSS and KEV from the SQLite cache, so a warm cache scores the same as an online scan. A missing or expired OSV query or advisory exits 2 instead of reporting zero findings. A missing EPSS row or KEV catalog stays a warning and counts as absent (#135).
- JSON `data_sources` records whether OSV, EPSS, and KEV came from the cache. `osv.fetched_at` is the stored fetch time when the rows came from the cache (#135).
- Markdown score lines are labeled as points and rounded to two decimal places. A table cut off at the top rows says how many findings were left out and points at the JSON or SARIF report (#135).
- Composer `dev-*` versions, `*.x-dev` versions, and `dist.type` `path` packages are skipped with a warning and are not sent to OSV (#135).
- Composer, Go, and the shell launcher exit 2 when they cannot start the binary, including a missing `PATCHSENSE_BINARY` and an unpublished release. The child process exit code is unchanged (#135).
- `--no-dev` reports the filtered package count on each lockfile (#135).
- `patchsense cache info --cache-dir DIR` and `patchsense cache clear --cache-dir DIR` are accepted (#135).
- A `bun.lock` or `bun.lockb` file produces a warning. It is still not parsed (#135).
- Composer, Go, and the Docker entrypoint say release `v0.1.0` is not published yet when the GitHub Release or archive is missing (HTTP 404), and they list `cargo install`, a source build, and `PATCHSENSE_BINARY`. `PATCHSENSE_BINARY` skips the download. A Go pseudo-version from `@latest` before any tag still requests release `v0.1.0` and says so (#123, #124).
- `.github/workflows/pypi.yml` no longer uses `matrix` in a job-level `if`, so GitHub accepts the file. Publish still runs only on tags whose names start with `v`.
- The GitLab template accepts `PATCHSENSE_VERSION` as `0.1.0` or `v0.1.0` and does not request tag `vv0.1.0`.

### Changed

- User-facing text is English only. Tier labels are Critical, Review, and Defer. The `--lang` flag is removed. An existing `explain.lang` key is ignored and warns.
