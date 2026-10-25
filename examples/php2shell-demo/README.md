# PHP2Shell demo

This example pins the PHP runtime at **8.3.35**.

PHP2Shell is the pair of critical PHP bugs disclosed on 21 October 2026:

- CVE-2026-109618
- CVE-2026-109619

Fixed upstream releases are PHP **8.5.12**, **8.4.27**, **8.3.36**, and **8.2.35**. 8.3.35 is the last vulnerable patch on the 8.3 line. PHP 8.1 and older are outside upstream support.

`composer.lock` records that pin under `platform.php`. Composer does not install the interpreter; the pin is here so a lockfile scan can see the vulnerable version. There is no Packagist library to bump.

On 25 October 2026 a live scan of this directory (`patchsense scan examples/php2shell-demo`) parsed the `php` 8.3.35 platform package and OSV returned no advisory. The GIF in `docs/demo.gif` therefore uses `examples/kev-log4shell` and CVE-2021-44228, which is in CISA KEV.
