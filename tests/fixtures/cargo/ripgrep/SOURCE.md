# ripgrep `Cargo.lock`

- Repository: https://github.com/BurntSushi/ripgrep
- Tag: `14.1.1`
- Commit: `4649aa9700619f94cf9c66876e9549d83420e16c` (2024-09-09)
- Files: `Cargo.lock`, root `Cargo.toml`, and each workspace member `Cargo.toml` under `crates/`
- License: Unlicense OR MIT
- Retrieved: 2026-10-25

Not trimmed. Member manifests are included so `direct` can be read from the workspace. Path crates (`globset`, `grep`, `ignore`, and the `grep-*` crates) stay out of the package list. `memmap2` is the renamed `memmap` dependency. `regex` is only a dev-dependency. `jemallocator` is a target-specific dependency.
