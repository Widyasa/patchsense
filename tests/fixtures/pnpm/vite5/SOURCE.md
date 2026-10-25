# vite `pnpm-lock.yaml` (trimmed, lockfileVersion 6.0)

- Repository: https://github.com/vitejs/vite
- Tag: `v5.0.0`
- Commit: `0c3125833033fec4356ab4e90e806e02e8644c40` (2023-11-16)
- File: `pnpm-lock.yaml`
- License: MIT
- Retrieved: 2026-10-25

Trim: the original lockfile has 1215 package entries and many importers. This fixture keeps the root importer (`.`) entries for `@babel/types` and `@rollup/plugin-typescript`, plus the package objects for those two keys and the transitive `to-fast-properties@2.0.0` named by `@babel/types`. The `@rollup/plugin-typescript` key keeps its peer suffix. Other importers, settings, and packages were dropped. Integrity hashes and dependency versions are unchanged.
