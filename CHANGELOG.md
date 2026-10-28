# Changelog

All notable changes to PatchSense are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - unreleased

First release. The date is filled in when the `v0.1.0` tag is created. Tagging and publishing are done by Widya; see [`docs/release-checklist.md`](docs/release-checklist.md).

### Fixed

- `.github/workflows/pypi.yml` no longer uses `matrix` in a job-level `if`, so GitHub accepts the file. Publish still runs only on tags whose names start with `v`.
- The GitLab template accepts `PATCHSENSE_VERSION` as `0.1.0` or `v0.1.0` and does not request tag `vv0.1.0`.

### Changed

- User-facing text is English only. Tier labels are Critical, Review, and Defer. The `--lang` flag is removed. An existing `explain.lang` key is ignored and warns.

### Added

- Composer package `widyasa/patchsense`. `vendor/bin/patchsense` downloads the matching GitHub Release binary, checks sha256, and runs it. No Rust toolchain is required.
- Go launcher `github.com/Widyasa/patchsense/go/cmd/patchsense`. `go install` / `go run` download the matching GitHub Release binary, check sha256, and run it. No Rust toolchain is required.
- Docker entrypoint `scripts/fetch-release.sh`. `docker build` stays local; the image is not pushed. On Alpine x64 it downloads the musl release archive and checks sha256.
- Lockfile parsers for npm, pnpm, Yarn, Poetry, `requirements.txt`, Composer, Go, Maven, and Cargo.
- OSV matching with EPSS, CISA KEV, and CVSS, plus a 0–100 priority score.
- Table, JSON, SARIF, markdown, and GitLab Dependency Scanning reports.
- `patchsense comment` for GitHub pull requests and GitLab merge requests.
- `patchsense mcp` tools and `patchsense scan --explain` for a local read-only agent.
- `patchsense init`, including `--agent` and `--print-mcp-config`.
- GitHub composite action, GitLab CI template, cargo-dist installers, and a maturin wheel for pip.
