# vite `pnpm-lock.yaml` (trimmed, lockfileVersion 9.0)

- Repository: https://github.com/vitejs/vite
- Tag: `v6.0.0`
- Commit: `814120f2ad387ca3d1e16c7dd403b04ca4b97f75` (2024-11-26)
- File: `pnpm-lock.yaml`
- License: MIT
- Retrieved: 2026-10-25

Trim: the original lockfile has 1319 packages and snapshots. This fixture keeps the root importer entries `@eslint/js`, `@type-challenges/utils`, and `conventional-changelog-cli` (peer suffix kept), their `packages` and `snapshots` objects, and `add-stream@1.0.0` because the real `conventional-changelog-cli` snapshot depends on it. Integrity hashes and versions are unchanged. Other dependency names inside that snapshot were kept; their package objects were dropped.
