# Release checklist

Phase A is done. Kodi published `patchsense` 0.1.0 and `patchsense-core` 0.1.0 to crates.io from `d824a4b` on 2026-10-28. There is still no git tag and no GitHub Release.

Phase B publishes the binary channels after GitHub Actions billing is fixed. The workspace version is `0.1.2` and the only crate is `patchsense` (library and binary). Publish that crate only. After a single-crate `patchsense` release is live, Kodi or Widya yanks `patchsense-core` 0.1.0. Do not yank it before that release is on the index, and do not yank it from a pull request.

Do not push `v0.1.0`. The binary-channel tag and `v0` are created in Phase B. `v0` points at that commit. This tree's version is `0.1.2`.

Phase B status (2026-10-29): GitHub Actions is disabled on the repository (billing lock), so Kodi built `v0.1.2` locally with cargo-dist 0.33.1 (cargo-zigbuild for Linux glibc 2.17 and macOS, cargo-xwin for Windows) from `ba0552e`, pushed tags `v0.1.2` and `v0`, created the GitHub Release with every archive, installer, `sha256.sum` and `dist-manifest.json`, and pushed `Formula/patchsense.rb` to `Widyasa/homebrew-tap`. Go works through proxy.golang.org. npm, PyPI and Packagist wait for Widya's credentials (B3 and B5); the built npm tarball and wheels are not in git.

`CHANGELOG.md` has `## [0.1.0] - 2026-10-28`, `## [0.1.1]`, and `## [0.1.2] - 2026-10-29`. `0.1.2` is the docs README release. Do not tag the commit until Phase B.

## Phase A — v0.1.0, crates.io only

Status: complete. The commands in this phase are the record of the 0.1.0 publish. This checkout has no `patchsense-core` package. Do not run them again.

Widya runs this from a laptop. GitHub Actions does not publish this release. Do not push a tag.

### A1. Pre-flight

From a clean checkout of the commit you will publish:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo package --list -p patchsense-core
cargo publish --dry-run -p patchsense-core
cargo package --list -p patchsense
cargo publish --dry-run -p patchsense
```

Core first, then the CLI. Publish order is the same.

Checked on 2026-10-28 against the two-crate tree at `d824a4b`, before `patchsense-core` 0.1.0 existed on crates.io. These counts are not the current package:

- `cargo package --list -p patchsense-core` lists 67 files, including `LICENSE-MIT`, `LICENSE-APACHE`, and `README.md`.
- `cargo package --list -p patchsense` lists 35 files, including `LICENSE-MIT`, `LICENSE-APACHE`, and `README.md`.
- `cargo publish --dry-run -p patchsense-core` verifies the crate and stops with `aborting upload due to dry run`. Repeat it on the merged master before the real publish.
- `cargo package --no-verify -p patchsense` writes the `.crate` (35 files). `cargo publish --dry-run -p patchsense` still fails with `no matching package named patchsense-core` until core 0.1.0 is on the index. The CLI depends on `patchsense-core` version `0.1.0` with a path, and the publish dry-run rewrites that path to the registry. Repeat the CLI dry-run after step A4. A failure before that is not a metadata bug.

Metadata on both crates, inherited from the workspace unless noted:

| Field | Value |
|---|---|
| version | `0.1.0` |
| license | `MIT OR Apache-2.0` |
| edition | 2021 |
| rust-version | 1.99 |
| authors | Widya Yasa |
| repository, homepage | `https://github.com/Widyasa/patchsense` |
| readme | repository `README.md`, packaged as `README.md` |
| keywords | `security`, `cve`, `osv`, `lockfile`, `dependencies` (five, the crates.io maximum) |
| categories | `patchsense-core`: `development-tools`. `patchsense`: `command-line-utilities`, `development-tools` |
| description | core: library for lockfile parsing, OSV matching, and priority scoring. CLI: prioritize vulnerabilities from lockfiles using OSV, EPSS, and CISA KEV |
| include / exclude | unset. Cargo's default file set. No path outside the crate directory is pulled in except the README, which Cargo copies into the package |
| license files | `LICENSE-MIT` and `LICENSE-APACHE` are symlinked into each crate directory. `cargo package` follows the links and stores both files in each `.crate`. The SPDX `license` field stays `MIT OR Apache-2.0` |

That split was the 0.1.0 publish. From `0.1.1` on, the only crate is `patchsense`. This tree is `0.1.2`, with categories `command-line-utilities` and `development-tools` and the workspace description. `LICENSE-MIT` and `LICENSE-APACHE` stay symlinked in `crates/patchsense`. `include` stays unset. The packaged README is `crates/patchsense/README.md`.

Names. Stop if either crate name is already taken by someone else:

```bash
cargo info patchsense-core
cargo info patchsense
```

npm and PyPI name checks belong to Phase B. They are not part of this publish.

### A2. Confirm the changelog date

`CHANGELOG.md` already says `## [0.1.0] - 2026-10-28`. If the publish is a different calendar day, change that heading on `master` first. Do not tag that commit.

### A3. Log in

`cargo login` reads Widya's crates.io API token. Do not commit it, do not add it as a GitHub secret, and do not paste it into a log. `export CARGO_REGISTRY_TOKEN=...` in a local shell is the same credential. No workflow in this repo reads that variable.

### A4. Publish

```bash
cargo publish -p patchsense-core
```

Wait until the index shows 0.1.0:

```bash
cargo info patchsense-core
```

Then the CLI dry-run can resolve the dependency. Publish the CLI only after that dry-run says it would upload:

```bash
cargo publish --dry-run -p patchsense
cargo publish -p patchsense
```

### A5. Verify

In a clean directory, not this checkout:

```bash
cargo install patchsense --locked
patchsense --version
```

Expect `patchsense 0.1.0`.

Stop. Do not push `v0.1.0` or `v0`. npm, pip, Composer, Go, Homebrew, Docker, and the shell installer stay unpublished.

## Phase B — binary channels, after billing is fixed

Binary channels: GitHub Release binaries via cargo-dist, npm, PyPI, Packagist/Composer, Go, Homebrew, the shell installer, and the Docker entrypoint (local image, musl archive from the release).

### B1. Confirm CI

GitHub Actions on `master` must be green. Do not tag while workflows refuse to start.

### B2. Homebrew tap

Create a public repository `Widyasa/homebrew-tap`. `dist-workspace.toml` sets `tap = "Widyasa/homebrew-tap"`. The release workflow checks that repo out and pushes `Formula/patchsense.rb`.

### B3. Secrets and the PyPI publisher

Create these in the GitHub UI. Do not commit the values and do not put them on a command line that gets logged.

| Secret | Where it is used |
|---|---|
| `NPM_TOKEN` | Repository secret on `Widyasa/patchsense`. `.github/workflows/release.yml` job `publish-npm` passes it as `NODE_AUTH_TOKEN` and runs `npm publish --access public`. The token needs permission to publish the unscoped package `patchsense`. |
| `HOMEBREW_TAP_TOKEN` | Repository secret on `Widyasa/patchsense`. Job `publish-homebrew-formula` uses it to push to `Widyasa/homebrew-tap`. Contents write on that tap is enough. |

Do not add `CARGO_REGISTRY_TOKEN` to GitHub. Crate publishes stay on the laptop, with `cargo login`.

PyPI does not use a password. Add a pending trusted publisher on pypi.org for the project `patchsense`:

- Owner: `Widyasa`
- Repository: `patchsense`
- Workflow name: `pypi.yml`
- Environment name: leave empty

`.github/workflows/pypi.yml` requests `id-token: write` and calls `pypa/gh-action-pypi-publish@release/v1` with no password and no GitHub environment.

### B4. Publish `patchsense`, yank `patchsense-core`, push the tags

The workspace version is `0.1.2`. Publish only `patchsense`. There is no second crate in this tree.

Launcher version constants in `go/cmd/patchsense`, `bin/patchsense`, `composer.json`, and `scripts/fetch-release.sh` still request GitHub Release `v0.1.0`. Bump those constants to the tag you push (the workspace version at that commit) so the launchers look for the release that tag creates. Do not tag until that commit is on `master`.

```bash
cargo publish --dry-run -p patchsense
cargo publish -p patchsense
cargo info patchsense
```

Wait until the index shows `patchsense` at the version you published (`0.1.2` for this tree).

Then yank the deprecated library. Kodi or Widya runs this after the single-crate `patchsense` release is live (`0.1.2` for this tree), not before, and not from CI:

```bash
cargo yank --version 0.1.0 patchsense-core
```

Yank hides `patchsense-core` 0.1.0 from new resolutions. It does not delete the crate. `patchsense` 0.1.0 on crates.io depends on it, so a fresh `cargo install patchsense --version 0.1.0` will not resolve after the yank. That is the point of the single-crate release: install the current `patchsense` (`0.1.2` in this tree). A lockfile that already pinned `patchsense-core` 0.1.0 can still fetch a yanked version. Do not yank `patchsense` 0.1.0 unless that is a separate decision. Do not yank `patchsense` 0.1.1 or 0.1.2.

Annotated tags. Pushing `v0.1.2` starts `.github/workflows/release.yml` (GitHub Release, shell and PowerShell installers, npm, Homebrew) and `.github/workflows/pypi.yml` (wheels and PyPI). cargo-dist creates the GitHub Release. There is no separate release step to click.

```bash
git tag -a v0.1.2 -m "patchsense 0.1.2"
git push origin v0.1.2
```

The composite action example is `uses: Widyasa/patchsense@v0`. That ref is a moving major tag:

```bash
git tag -a v0 -m "patchsense action v0" v0.1.2
git push origin v0
```

On later 0.1.x releases, move `v0` (`git tag -f -a v0 -m "patchsense action v0" v0.1.x`, then `git push --force origin v0`). Do not force-push `master`.

`v0.1.2-rc.1` makes cargo-dist open a GitHub prerelease. The npm and Homebrew jobs skip prereleases. `pypi.yml` publishes every tag that starts with `v`, including an rc tag. Do not push an rc tag unless a PyPI pre-release is intended.

### B5. Packagist, Go, Docker

Do this after the `v0.1.2` GitHub Release has `dist-manifest.json` and the archives. `composer require` and `go install` can be typed before that. The first run then says the release is not published yet. `PATCHSENSE_BINARY=/path/to/patchsense` runs a binary you already built and skips the download.

Packagist:

1. Sign in to packagist.org as the GitHub user `Widyasa`.
2. Submit `https://github.com/Widyasa/patchsense`. `composer.json` is at the repository root. The package name is `widyasa/patchsense`.
3. Enable the Packagist GitHub webhook so later tags update the package. Do not commit a token.
4. Packagist versions come from git tags. The `"version"` field in `composer.json` is for path installs and is ignored by Packagist. `bin/patchsense` constant `PATCHSENSE_VERSION` must match the tag (`0.1.2` for `v0.1.2`).

Go:

There is no separate Go registry to create. The module path is `github.com/Widyasa/patchsense`, so tag `v0.1.2` is the module version (`go/cmd/patchsense`, constant `patchsenseVersion`). The first `go install github.com/Widyasa/patchsense/go/cmd/patchsense@v0.1.2` makes proxy.golang.org fetch that tag. The launcher then downloads the release binary.

Docker:

There is no image publish step. Users build [`Dockerfile`](../Dockerfile) themselves. Do not push to Docker Hub or GHCR. On Alpine x64 the entrypoint downloads the musl archive from the GitHub Release.

### B6. Verify every channel

After the Release and PyPI workflows succeed, and after Packagist has the package:

```bash
cargo install patchsense --locked
patchsense --version
npx --yes patchsense --version
pip install --upgrade patchsense
patchsense --version
composer require --dev widyasa/patchsense
vendor/bin/patchsense --version
go install github.com/Widyasa/patchsense/go/cmd/patchsense@v0.1.2
patchsense --version
brew install Widyasa/tap/patchsense
patchsense --version
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/Widyasa/patchsense/releases/download/v0.1.2/patchsense-installer.sh | sh
patchsense --version
docker build -t patchsense .
docker run --rm patchsense --version
```

Each one should print `patchsense 0.1.2`. The `go install` line puts the launcher on `PATH` as `patchsense`; run it somewhere that is not still shadowed by a different `patchsense`.

The cargo-dist npm package does not verify sha256. The shell installer, Homebrew formula, Composer proxy, Go launcher, and Docker entrypoint do.
