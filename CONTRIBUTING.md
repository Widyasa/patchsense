# Contributing

PatchSense is a Rust workspace: `crates/patchsense-core` (library) and `crates/patchsense` (binary). Edition 2021. `rust-version` in the root `Cargo.toml` is the MSRV (`1.99`). `unsafe_code` is forbidden.

## Checks

Run these before a push. CI is not a substitute while GitHub Actions are unavailable.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Tests must not call the network. Use the fixtures under `tests/fixtures/` and `wiremock`. Update snapshots with `INSTA_UPDATE=1 cargo test` and review the diff.

## Changes

Open a GitHub issue first. Use a branch `w<week>-t<task>-<slug>` for a task in [`docs/TASKS.md`](docs/TASKS.md), or another descriptive branch for other work. The pull request says `Closes #<n>`. Do not commit directly to `master`.

Do not publish to crates.io, npm, PyPI, or Homebrew, and do not push git tags or create GitHub Releases. Those steps are done by Widya and are listed in `docs/release-checklist.md` once the release task adds that file. Do not add tokens or change repository settings.

## Commit messages

Use a Conventional Commits subject. Explain why in the body when the subject is not enough.
