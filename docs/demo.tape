# Demo GIF for the Log4Shell example.
#
# examples/php2shell-demo pins PHP 8.3.35, but on 25 Oct 2026 OSV returned
# no advisory for Packagist package `php`. This tape scans
# examples/kev-log4shell instead. That POM pins log4j-core 2.14.1
# (CVE-2021-44228), which is in the CISA KEV catalog.
#
# Requires `patchsense` on PATH and the vhs tools (ttyd, ffmpeg).
# The table is English (Critical / Review / Defer). No language flag.

Output docs/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1400
Set Height 780
Set Padding 24
Set TypingSpeed 40ms

Type "patchsense scan examples/kev-log4shell"
Enter
Sleep 15s
