# Release checklist for v0.1.0

This file is the command list for Widya. The version in the workspace is already `0.1.0`. `CHANGELOG.md` already has the `0.1.0` notes with the date left as `unreleased`. Nothing in this repository has been tagged or published.

Do these steps from a clean checkout of `master` after the billing lock on GitHub Actions is cleared. A tag push does not build artifacts while Actions refuse to start.

## 1. Recheck the package name

The locked name is unscoped `patchsense` (crate `patchsense-core` as well). On 25 Oct 2026 the PRD recorded that name as still free. Check again immediately before publishing:

```bash
cargo info patchsense-core
cargo info patchsense
npm view patchsense version
pip index versions patchsense
```

Stop if any of those already belong to someone else.

## 2. Create the Homebrew tap

Create a public repository `Widyasa/homebrew-tap`. `dist-workspace.toml` sets `tap = "Widyasa/homebrew-tap"`. The release workflow checks that repo out and pushes `Formula/patchsense.rb`.

## 3. Create secrets

Create these in the GitHub UI. Do not commit the values and do not put them on a command line that gets logged.

| Secret | Where it is used |
|---|---|
| `NPM_TOKEN` | Repository secret on `Widyasa/patchsense`. `.github/workflows/release.yml` job `publish-npm` passes it as `NODE_AUTH_TOKEN` and runs `npm publish --access public`. The token needs permission to publish the new unscoped package `patchsense`. |
| `HOMEBREW_TAP_TOKEN` | Repository secret on `Widyasa/patchsense`. Job `publish-homebrew-formula` uses it to push to `Widyasa/homebrew-tap`. Contents write on that tap is enough. |
| `CARGO_REGISTRY_TOKEN` | Local environment only. No workflow reads it. `cargo login` or `export CARGO_REGISTRY_TOKEN=...` before `cargo publish`. |

PyPI does not use a password. Add a **pending trusted publisher** on pypi.org for the new project `patchsense`:

- Owner: `Widyasa`
- Repository: `patchsense`
- Workflow name: `pypi.yml`
- Environment name: leave empty

`.github/workflows/pypi.yml` requests `id-token: write` and calls `pypa/gh-action-pypi-publish@release/v1` with no password and no GitHub environment.

## 4. Set the changelog date

In `CHANGELOG.md`, replace `## [0.1.0] - unreleased` with `## [0.1.0] - YYYY-MM-DD` using the day of the tag. Commit that on `master` before tagging. Do not invent the date ahead of the tag.

## 5. Publish the crates

`cargo publish --dry-run -p patchsense-core` already succeeded in W6-T4. `cargo publish --dry-run -p patchsense` cannot succeed until `patchsense-core` 0.1.0 is on the crates.io index, because the binary depends on `patchsense-core` version `0.1.0`.

```bash
cargo publish -p patchsense-core
# wait until the index shows 0.1.0
cargo publish --dry-run -p patchsense
cargo publish -p patchsense
```

Publish `patchsense-core` first. Publish `patchsense` only after the dry-run reports that it would upload.

## 6. Tag

Annotated tag on the changelog commit. Pushing it starts `.github/workflows/release.yml` (GitHub Release, shell and PowerShell installers, npm, Homebrew) and `.github/workflows/pypi.yml` (wheels and PyPI).

```bash
git tag -a v0.1.0 -m "patchsense 0.1.0"
git push origin v0.1.0
```

The composite action example is `uses: Widyasa/patchsense@v0`. That ref is a moving major tag, separate from `v0.1.0`:

```bash
git tag -a v0 -m "patchsense action v0" v0.1.0
git push origin v0
```

On later 0.1.x releases, move `v0` to the new commit (`git tag -f -a v0 -m "patchsense action v0" v0.1.x` then `git push --force origin v0`). Do not force-push `master`.

### Optional pre-release tag

`v0.1.0-rc.1` makes cargo-dist build every target and open a GitHub prerelease. The npm and Homebrew jobs skip prereleases. `pypi.yml` publishes **every** tag that starts with `v`, including `v0.1.0-rc.1`. Do not push an rc tag unless a PyPI pre-release is intended.

Local checks that already ran, and that do not need a tag: `dist plan`, `dist build --target x86_64-unknown-linux-gnu`, and `maturin build --release` followed by `pip install` of that wheel. `pypi.yml` is valid (`actionlint` clean). Publish still runs only for tags whose names start with `v`.

## 7. Packagist and the Go module

Do this after the `v0.1.0` GitHub Release has `dist-manifest.json` and the archives. `composer require` and `go install` can succeed before that, but the first run of the launcher downloads the archive and fails if it is missing.

Packagist:

1. Sign in to packagist.org as the GitHub user `Widyasa`.
2. Submit `https://github.com/Widyasa/patchsense`. `composer.json` is at the repository root. The package name is `widyasa/patchsense`.
3. Enable the Packagist GitHub webhook so later tags update the package. Do not commit a token.
4. Packagist versions come from git tags. The `"version"` field in `composer.json` is for path installs and is ignored by Packagist. `bin/patchsense` constant `PATCHSENSE_VERSION` must stay `0.1.0` for tag `v0.1.0`.

Go:

There is no separate Go registry to create. The module path is `github.com/Widyasa/patchsense`, so tag `v0.1.0` is the module version (`go/cmd/patchsense`, constant `patchsenseVersion`). The first `go install github.com/Widyasa/patchsense/go/cmd/patchsense@v0.1.0` makes proxy.golang.org fetch that tag. The launcher then downloads the release binary. No extra `go/v0.1.0` tag.

Docker:

There is no image publish step. Users build [`Dockerfile`](../Dockerfile) themselves. Do not push to Docker Hub or GHCR as part of this release.

## 8. Confirm the installs

After the Release and PyPI workflows succeed, and after Packagist has the package:

```bash
npx --yes patchsense --version
pip install --upgrade patchsense
patchsense --version
composer require --dev widyasa/patchsense
vendor/bin/patchsense --version
go install github.com/Widyasa/patchsense/go/cmd/patchsense@v0.1.0
patchsense --version
brew install Widyasa/tap/patchsense
patchsense --version
cargo install patchsense --locked
patchsense --version
```

Each one should print `patchsense 0.1.0`. The `go install` line puts the launcher on `PATH` as `patchsense`; run it somewhere that is not still shadowed by a different `patchsense`.

The cargo-dist npm package does not verify sha256. The shell installer, Homebrew formula, Composer proxy, Go launcher, and Docker entrypoint do.
