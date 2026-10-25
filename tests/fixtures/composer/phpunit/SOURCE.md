# phpunit `composer.lock` (trimmed)

- Repository: https://github.com/sebastianbergmann/phpunit
- Tag: `10.5.0`
- Commit: `80cab181aebc2efac422940443e28db556137637` (2023-12-01)
- File: `composer.lock`
- License: BSD-3-Clause
- Retrieved: 2026-10-25

Trim: the original lockfile has 25 production packages and no `packages-dev` entries. This fixture keeps `myclabs/deep-copy` 1.11.1 and `nikic/php-parser` `v4.17.1`. Names and versions are unchanged.

`composer.json` keeps `php` and `myclabs/deep-copy` from `require` at the same tag. `nikic/php-parser` is not in `require`; it is transitive.
