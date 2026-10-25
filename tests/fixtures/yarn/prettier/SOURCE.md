# prettier `yarn.lock` (trimmed, yarn lockfile v1)

- Repository: https://github.com/prettier/prettier
- Tag: `2.8.0`
- Commit: `dcc0623911f8b352eda18f60683eb1a232d6c2bd` (2022-11-23)
- File: `yarn.lock`
- License: MIT
- Retrieved: 2026-10-25

Trim: the original lockfile has 909 package blocks. This fixture keeps `@babel/code-frame@7.0.0` and `@babel/highlight@^7.0.0`, `@babel/highlight@^7.16.7`. Headers, versions, integrity hashes, and the dependency lists are unchanged.

`package.json` is a trim of the same tag. `@babel/code-frame` is a production dependency there. `@babel/highlight` is not listed in `dependencies` or `devDependencies`; it is only required by the code-frame block.
