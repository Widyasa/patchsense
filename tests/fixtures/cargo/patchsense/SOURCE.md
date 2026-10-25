# PatchSense `Cargo.lock`

- Repository: https://github.com/Widyasa/patchsense
- Commit: `2facd3d` (master after W2-T6, 2026-10-25)
- Files: `Cargo.lock`, root `Cargo.toml`, `crates/patchsense/Cargo.toml`, `crates/patchsense-core/Cargo.toml`
- License: MIT OR Apache-2.0

Not trimmed. Copied from this repository so the snapshot stays stable when later tasks add dependencies. Workspace members `patchsense` and `patchsense-core` are path packages and are not emitted. `assert_cmd` and `insta` are dev-dependencies. `anyhow` and `quick-xml` are normal dependencies. `memchr` is transitive.
