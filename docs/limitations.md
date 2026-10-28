# Limitations

These are known gaps. A warning is printed when the scanner can see the file. The other items are silent.

## `bun.lock`

`bun.lock` and `bun.lockb` are not parsed. A scan that sees one, outside `node_modules`, `vendor`, `target`, `.git`, `.venv`, and `venv`, adds a warning. The file is not sent to OSV. Other package managers that are not in the supported-lockfile list stay quiet.

## Platform packages

`composer.lock` records the PHP runtime and extensions under `platform` and `platform-dev`. A constraint such as `php: ^8.3` or `ext-curl: *` is not an installed version, so it is skipped. A concrete version, such as `php: 8.3.35` in the PHP2Shell example, is scanned. `ext-*` packages are not queried as PHP extensions.

## SARIF `startLine`

SARIF sets `startLine` to the line the parser stored. Most lockfile parsers do not record a line, so the region starts at line 1.

## Offline cache

`--offline` does not call the network. Every OSV query and advisory body has to already be in the SQLite cache and inside `[cache] ttl_hours_osv` (24 hours when the key is omitted). A missing row exits 2. A row that is present but older than the TTL also exits 2, and the error names the age and the TTL. The scan does not print a partial report. Fill the cache with a normal scan first.

EPSS and KEV use `ttl_hours_epss` and `ttl_hours_kev`. A missing row is a warning, and that signal counts as absent. A row that is present but older than its TTL is still used, and the warning names the age. The score does not drop because the row expired. The same warning is written into the Markdown report and into GitHub and GitLab comments. `--strict-cache`, or `strict_cache = true` in the config, exits 2 when a row is missing or expired. A config-sourced error says to set `[cache] strict_cache = false`.

An online scan reuses fresh cache rows and downloads again when a row is older than its TTL. `data_sources.*.from_cache` is true only when every row for that source came from the cache. `data_sources.osv.fetched_at` is the oldest stored fetch time in that case, not the clock of the current scan.
