# Yarn Berry `yarn.lock` (trimmed)

- Repository: https://github.com/yarnpkg/berry
- Tag: `@yarnpkg/cli/4.0.0`
- Commit: `c6764b28f8e8dbdac7ad318d6d98b5d5f0f4679e` (2023-10-22)
- File: `yarn.lock`
- License: BSD-2-Clause
- Retrieved: 2026-10-25

Trim: the original lockfile has about 1800 npm descriptors plus workspace and patch entries. This fixture keeps `__metadata`, `@aashutoshrathi/word-wrap@npm:^1.2.3`, `chalk@npm:^3.0.0`, the `semver@npm:^7.1.2` descriptor, `@yarnpkg/builder@workspace:...`, and the `fsevents@patch:...` descriptor. Versions, resolutions, and checksums are unchanged. The builder dependency list was shortened to `chalk` and `semver`.

`package.json` is a trim of the monorepo root at the same tag. `chalk` and `semver` are production dependencies there. `word-wrap` is not. Workspace and patch descriptors must not become packages.

The builder dependency map in the original file lists more packages. Those keys were removed in the trim; the resolution string is unchanged.
