# composer/composer `composer.lock` (trimmed)

- Repository: https://github.com/composer/composer
- Tag: `2.7.0`
- Commit: `96d107e2bfe61bb9eafe55a9d45bd7faed1dd461` (2024-02-08)
- File: `composer.lock`
- License: MIT
- Retrieved: 2026-10-25

Trim: the original lockfile has 28 production packages and 6 dev packages. This fixture keeps `composer/ca-bundle` 1.4.0, `justinrainbow/json-schema` `v5.2.13`, and dev package `symfony/phpunit-bridge` `v7.0.3`. Names and versions are unchanged. Source, dist, and autoload objects were dropped.

`composer.json` keeps the matching `require` and `require-dev` constraints from the same tag, including the `php` constraint. That constraint is not an installed version, so the parser does not emit a `php` package for it.
