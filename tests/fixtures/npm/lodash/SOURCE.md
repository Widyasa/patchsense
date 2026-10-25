# lodash `package-lock.json` (trimmed, lockfileVersion 1)

- Repository: https://github.com/lodash/lodash
- Tag: `4.17.21`
- Commit: `f299b52f39486275a9e6483b60a410e06520c538` (2021-02-20)
- File: `package-lock.json`
- License: MIT (Copyright OpenJS Foundation and other contributors, based on Underscore.js)
- Retrieved: 2026-10-25
- lockfileVersion: 1

Trim: the original `dependencies` object has 493 top-level packages. This fixture keeps `async`, `abbrev`, `JSV`, and `ansi-styles`. The `async` entry originally nested only `lodash` at 4.17.14 (vulnerable to GHSA-35jh-r3h4-6jhm, fixed in 4.17.21); that nested object is unchanged. Other dependency entries were dropped. Top-level metadata (`name`, `version`, `lockfileVersion`, `requires`) is unchanged.
