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

Local checks that already ran, and that do not need a tag: `dist plan`, `dist build --target x86_64-unknown-linux-gnu`, and `maturin build --release` followed by `pip install` of that wheel.

## 7. Confirm the installs

After the Release and PyPI workflows succeed:

```bash
npx --yes patchsense --version
pip install --upgrade patchsense
patchsense --version
brew install Widyasa/tap/patchsense
patchsense --version
cargo install patchsense --locked
patchsense --version
```

Each one should print `patchsense 0.1.0`.
