# lodash `yarn.lock` (trimmed, yarn lockfile v1)

- Repository: https://github.com/lodash/lodash
- Tag: `4.17.21`
- Commit: `f299b52f39486275a9e6483b60a410e06520c538` (2021-02-20)
- File: `yarn.lock`
- License: MIT
- Retrieved: 2026-10-25

Trim: the original lockfile has 544 package blocks. This fixture keeps `abbrev`, `ansi-styles`, `async`, and `chalk`. Headers, versions, and resolved URLs are unchanged. The nested `dependencies` list under `chalk` is unchanged.

`package.json` is a trim of the same tag. The original `devDependencies` object is much larger; this copy keeps `async` and `chalk`, which are the direct packages in the trimmed lockfile. `ansi-styles` is only a dependency of `chalk`, so it stays transitive.
