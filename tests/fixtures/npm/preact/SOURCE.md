# preact `package-lock.json` (trimmed)

- Repository: https://github.com/preactjs/preact
- Tag: `10.24.1`
- Commit: `3fe5d6b00fa6a7d0a1af83f2ea8822a7f82cdd6c` (2024-09-24)
- File: `package-lock.json`
- License: MIT (Copyright (c) 2015-present Jason Miller)
- Retrieved: 2026-10-25
- lockfileVersion: 3

Trim: the original `packages` map has 1226 entries. This fixture keeps the root package and these entries, unmodified:

- `node_modules/lodash`
- `node_modules/@actions/core`
- `node_modules/@actions/core/node_modules/uuid`
- `node_modules/@actions/github`

Root `devDependencies` / `dependencies` were reduced to the names of the retained top-level packages so the direct-dependency set still matches those entries. Other root metadata (`name`, `version`, `license`, `funding`) is unchanged.
