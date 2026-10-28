# Contributing

Thanks for helping with PatchSense. Contributions are licensed under `MIT OR Apache-2.0`, the same terms as the repository ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).

The workspace has two crates: `crates/patchsense-core` (library) and `crates/patchsense` (binary). Edition 2021. `unsafe_code` is forbidden.

## Fork and clone

Fork [Widyasa/patchsense](https://github.com/Widyasa/patchsense), then:

```bash
git clone https://github.com/<you>/patchsense.git
cd patchsense
git remote add upstream https://github.com/Widyasa/patchsense.git
git checkout master
git pull upstream master
```

## Prerequisites

- Rust at least **1.99**. That is `rust-version` in the root `Cargo.toml` (the MSRV). There is no `rust-toolchain.toml`; CI installs stable with the components below.
- `rustfmt` and `clippy`. With rustup: `rustup component add rustfmt clippy`.
- A C compiler on `PATH` as `cc`. `patchsense-core` depends on `rusqlite` with the `bundled` feature, which compiles SQLite.

Node, Python, and Go are not required to build or test. A live `patchsense scan` of a real project talks to OSV, EPSS, and CISA KEV, so that command needs a network. Tests must not.

## Build and run

```bash
cargo build --workspace
cargo run -p patchsense -- --version
cargo run -p patchsense -- scan --help
```

`cargo run -p patchsense -- --version` prints `patchsense 0.1.0` at the current workspace version.

```bash
cargo run -p patchsense -- scan examples/kev-log4shell
```

That example pins `log4j-core` 2.14.1 and needs the network. A TTY prints the table. A pipe prints JSON.

## Checks before you push

Run these on your branch. They match [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

This repository does not ship a Git hook. A clone will not run those commands for you. Run them yourself before every push. Do not push to `master`.

Tests must not call the network. Library tests use `FakeHttp` in `crates/patchsense-core/src/http.rs`, which never opens a socket. Binary integration tests use `wiremock` (a dev-dependency of `crates/patchsense`). Lockfile fixtures live under `tests/fixtures/`.

## Workflow

1. Open a GitHub issue, or pick an existing one, before you start.
2. Branch from current `master`. Items in [`docs/TASKS.md`](docs/TASKS.md) have used `w<week>-t<task>-<slug>`. Other work uses a short descriptive name.
3. Commit with a [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) subject. Put the area you changed in the scope:

   - `feat(scope): ...`
   - `fix(scope): ...`
   - `docs(scope): ...`
   - `refactor(scope): ...`
   - `chore(scope): ...`
   - `test(scope): ...`

   Explain why in the body when the subject is not enough.
4. Open a pull request into `master`. The body must reference the issue as `Closes #N`.
5. Do not push commits straight to `master`.

Publishing to crates.io, npm, PyPI, or Homebrew, and creating git tags or GitHub Releases, is listed in [`docs/release-checklist.md`](docs/release-checklist.md) and is not part of a contribution. Do not add tokens or change repository settings.

## Add a lockfile parser

Parsers are pure: file text in, a `ParsedLockfile` out. The registry is `crates/patchsense-core/src/lockfile/mod.rs`.

1. Add a module next to the existing ones (`npm.rs`, `pnpm.rs`, `yarn.rs`, `poetry.rs`, `requirements.rs`, `composer.rs`, `gosum.rs`, `maven.rs`, `cargo.rs`).
2. Implement `LockfileParser` (`ecosystem`, `matches`, `parse`). `matches` looks at the file name. Requirements files also match `requirements-*.txt`, `requirements_*.txt`, `requirements.*.txt`, `*.requirements.txt`, and any `.txt` file in a directory named `requirements`.
3. Register the type in the `PARSERS` slice and add the file name to `supported_file_names()`.
4. If the ecosystem is new, add a variant to `Ecosystem` in `crates/patchsense-core/src/model.rs`. The serde name is the OSV ecosystem string.
5. Put a real lockfile under `tests/fixtures/` and cover it with `insta` snapshots in the parser module. `crates/patchsense-core/tests/parser_robustness.rs` already runs every name from `supported_file_names()` through truncated fixtures and must keep passing.

## Add a report format

Document renderers live in `crates/patchsense-core/src/report/` (`json.rs`, `sarif.rs`, `markdown.rs`, `gitlab.rs`) and are re-exported from `report/mod.rs`. The terminal table is binary-only: `crates/patchsense/src/table.rs`.

1. Add the renderer. A document format belongs in `report/`; a terminal view belongs next to `table.rs`.
2. Add a variant to `ReportFormat` in `crates/patchsense/src/cli.rs`.
3. Handle it in `render_format` in `crates/patchsense/src/main.rs`.
4. Add or update the `insta` snapshot beside the renderer.

## Snapshot tests

`insta` is a dev-dependency of both crates. Snapshots sit in `snapshots/` directories next to the tests. To accept an intentional change:

```bash
INSTA_UPDATE=1 cargo test --workspace
```

A narrower filter is fine when you know which test moved. Review the `.snap` diff and commit it with the change. `cargo insta` is not a project dependency; the environment variable is enough.

## Security

Do not open a public issue for an undisclosed vulnerability in this repository. Use GitHub private vulnerability reporting from the [Security tab](https://github.com/Widyasa/patchsense/security) of `Widyasa/patchsense` (**Report a vulnerability**). Details are in [`SECURITY.md`](SECURITY.md). If that form is not available, contact the owner, Widya Yasa, on GitHub (`@Widyasa`) and wait for a reply before sharing details. There is no security email address.

A vulnerability in a third-party package that a scan reports belongs to that package's maintainers and to OSV.

## License

By contributing, you agree that your changes are available under `MIT OR Apache-2.0`.
