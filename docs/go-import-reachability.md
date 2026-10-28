# Go package-level import check

Not implemented. This is the design for the 2026-10-28 smoke test, where GO-2026-5932 (`x/crypto/openpgp`) was reported for a module that the project only imports as `x/crypto/argon2`.

## What a finding means today

`go.sum` supplies the module and version, for example `golang.org/x/crypto`. `affected_matches` in `crates/patchsense-core/src/osv.rs` compares that module name with `affected[].package.name` and the ecosystem `Go`. `advisory_from_json` keeps the id, aliases, summary, severity, references, and fixed versions. It does not keep `affected[].ecosystem_specific`.

The finding is a version match on the module. It is not evidence that the vulnerable package was imported.

## What OSV already provides

GO-2026-5932, fetched from `https://api.osv.dev/v1/vulns/GO-2026-5932` on 2026-10-28, looks like this:

- `affected[].package.name` is `golang.org/x/crypto`
- `affected[].ecosystem_specific.imports` is a list of `{ "path": "..." }`
- the paths are `golang.org/x/crypto/openpgp` and its subpackages (`packet`, `armor`, `clearsign`, `errors`, `elgamal`, `s2k`)
- this advisory has no `symbols` list

The Go vulnerability database puts the imported package on `imports[].path`. `imports[].symbols`, when present, names functions or methods inside that package. The field sits on the affected entry, not on the advisory root. An entry with no `imports` list cannot be filtered this way, and the finding should stay a version match.

## Check to build later

After a Go finding matches the module version:

1. Read `imports[].path` from the affected entry that matched. If that list is missing or empty, leave the finding as it is.
2. Read `.go` files under the scanned tree. Skip `vendor/`, `testdata/`, and the directories discovery already skips.
3. Collect paths from single-line imports and from `import (` blocks. An alias such as `argon2 "golang.org/x/crypto/argon2"` still carries the path.
4. If none of the advisory paths appear, add a note such as `imported package not seen`. Do not drop the finding. A later flag can hide those notes. Until then, version matches stay visible.
5. Do not match `symbols`. Searching call sites is a different check and is much noisier.

This is not reachability. It does not build a call graph, it does not apply build tags, and it does not ask the `go` command which files are part of the build. A file that is never compiled can still contain the import. A file generated during the build is invisible. That is enough to tell `openpgp` from `argon2`.

## Effort

One change, about the size of a lockfile parser:

- Keep the import paths while `advisory_from_json` already holds the raw document. No new HTTP client.
- A few hundred lines to scan `.go` files, plus a fixture module that imports `argon2` and a fixture advisory whose imports name `openpgp`.
- No `go` toolchain, and no port of govulncheck.

Call-graph reachability (the build list, symbol matches, build tags) is a separate project and needs the `go` tool. Do not start it as part of this note.
