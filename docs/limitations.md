# Limitations

These are known gaps. A warning is printed when the scanner can see the file. The other items are silent.

## `bun.lock`

`bun.lock` and `bun.lockb` are not parsed. A scan that sees one, outside `node_modules`, `vendor`, `target`, `.git`, `.venv`, and `venv`, adds a warning. The file is not sent to OSV. Other package managers that are not in the supported-lockfile list stay quiet.

## Platform packages

`composer.lock` records the PHP runtime and extensions under `platform` and `platform-dev`. A constraint such as `php: ^8.3` or `ext-curl: *` is not an installed version, so it is skipped. A concrete version, such as `php: 8.3.35` in the PHP2Shell example, is scanned. `ext-*` packages are not queried as PHP extensions.

## SARIF `startLine`

SARIF sets `startLine` to the line the parser stored. Most lockfile parsers do not record a line, so the region starts at line 1.

## Offline cache

`--offline` does not call the network. Every OSV query and advisory body has to already be in the SQLite cache. If any of those rows is missing or expired, the scan exits 2 and does not print a partial report. Fill the cache with a normal scan first.

EPSS and KEV use the same cache. A missing EPSS row or a missing KEV catalog is a warning, and that signal counts as absent. The finding is still reported. A warm cache that has OSV, EPSS, and KEV scores the same as the online scan.

An online scan reuses fresh cache rows. `data_sources.*.from_cache` is true only when every row for that source came from the cache. `data_sources.osv.fetched_at` is the oldest stored fetch time in that case, not the clock of the current scan.
