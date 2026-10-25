# Log4Shell KEV demo

This example declares Maven `org.apache.logging.log4j:log4j-core` **2.14.1**.

That version is affected by **CVE-2021-44228** (Log4Shell). CISA lists CVE-2021-44228 in the Known Exploited Vulnerabilities catalog. A live `patchsense scan` of this directory is what `docs/demo.gif` records.

`examples/php2shell-demo` still pins PHP 8.3.35. On 25 October 2026, OSV returned no advisory for the Packagist package `php` at that version, so the GIF uses this KEV CVE instead.
