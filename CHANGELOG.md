# Changelog

All notable changes to PatchSense are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - unreleased

First release. The date is filled in when the `v0.1.0` tag is created. Tagging and publishing are done by Widya; see [`docs/release-checklist.md`](docs/release-checklist.md).

### Changed

- User-facing text is English only. Tier labels are Critical, Review, and Defer. The `--lang` flag is removed. An existing `explain.lang` key is ignored and warns.

### Added

- Lockfile parsers for npm, pnpm, Yarn, Poetry, `requirements.txt`, Composer, Go, Maven, and Cargo.
- OSV matching with EPSS, CISA KEV, and CVSS, plus a 0–100 priority score.
- Table, JSON, SARIF, markdown, and GitLab Dependency Scanning reports.
- `patchsense comment` for GitHub pull requests and GitLab merge requests.
- `patchsense mcp` tools and `patchsense scan --explain` for a local read-only agent.
- `patchsense init`, including `--agent` and `--print-mcp-config`.
- GitHub composite action, GitLab CI template, cargo-dist installers, and a maturin wheel for pip.
