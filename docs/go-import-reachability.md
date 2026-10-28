# Go package-level import check

Implemented. A `go.sum` finding is still a version match on the module. When the advisory lists import paths and none of them appear in the project's `.go` files, the finding stays and carries the note `imported package not seen`.

This is the check for the 2026-10-28 smoke test, where GO-2026-5932 (`golang.org/x/crypto/openpgp`) was reported for a module that the project only imports as `golang.org/x/crypto/argon2`.

## What is stored

`advisory_from_json` reads `affected[].ecosystem_specific.imports` from entries whose package name and ecosystem match the installed module. Each item keeps:

- `path`, the Go import path
- `symbols`, when OSV sent them

Paths are deduped. Symbols for the same path are merged. The list is empty for other ecosystems and for Go advisories that omit `imports`. The SQLite cache still stores the raw OSV document, so an older cache row parses without a schema change. An offline scan re-reads that JSON and runs the same check.

`symbols` are not matched. Searching call sites is a different check.

## What is scanned

For a Go finding whose advisory has a non-empty import list, PatchSense walks `.go` files under the scan root (the parent directory when the root is a lockfile). It collects:

- `import "path"`
- grouped `import (` blocks
- aliases (`argon2 "golang.org/x/crypto/argon2"`), dot imports (`. "path"`), and blank imports (`_ "path"`)
- imports in files that start with `//go:build` or `// +build`

Build tags are not evaluated. A file that would be excluded by `GOOS` or `GOARCH` still counts, because the scan does not ask the `go` command which files are built.

Skipped by default, and configurable in `[scan.go_imports]`:

| Key | Default | Effect |
|---|---|---|
| `skip_vendor` | `true` | skip a directory named `vendor` |
| `skip_testdata` | `true` | skip a directory named `testdata` |
| `skip_tests` | `true` | skip `*_test.go` |

`node_modules`, `target`, `.git`, `.venv`, and `venv` are always skipped. Directory symlinks are not followed.

## Match rule

An advisory path matches an import when the two strings are equal, or when the import is that path plus a subpackage (`advisory_path + "/" + rest`).

Importing `golang.org/x/crypto/openpgp/packet` matches an advisory path of `golang.org/x/crypto/openpgp`. Importing `golang.org/x/crypto` or `golang.org/x/crypto/argon2` does not. `golang.org/x/crypto/openpgp2` does not match `golang.org/x/crypto/openpgp`.

## Note and score

If no listed path matches, the finding is kept and `import_note` is `imported package not seen`. The score and the tier stay on the version-match formula (KEV, EPSS, CVSS, direct, fix). There is no downgrade.

The note is the visible flag. A missing import is not proof the package is unused: tests and vendor trees are skipped, build tags are not applied, and files generated during the build are invisible. Lowering the score would also change `--fail-on` for a heuristic. When the advisory has no imports data, `import_note` is omitted and the report matches the previous output.

The note is shown in:

- the table advisory cell
- JSON `findings[].import_note` (omitted when unset; see `schemas/report.v1.json`)
- the SARIF result message
- markdown, which is what GitHub pull-request and GitLab merge-request comments render
- the GitLab Dependency Scanning description
- `patchsense scan --explain`
- MCP `scan_project` (markdown and JSON), `get_finding`, and `explain_score`

## Out of scope

Call-graph reachability, symbol matches, and asking `go` which files are part of the build are a separate project. This check does not drop findings.
