# Security

## Scanning your own project

PatchSense reads lockfiles and talks to the public OSV, EPSS, and CISA KEV endpoints. It does not upload your source. Cache files stay on the machine that ran the scan (`patchsense cache info` prints the path).

`scan --explain` sends a prompt built from finding data to a coding agent already installed on that machine. The prompt is not sent to a PatchSense server. Treat the agent's text as untrusted: the product labels it `AI explanation, may be wrong`.

## Reporting a vulnerability in PatchSense

Please do not open a public issue for an undisclosed vulnerability in this repository.

If GitHub private vulnerability reporting is enabled for [Widyasa/patchsense](https://github.com/Widyasa/patchsense), use that form. Otherwise contact the owner, Widya Yasa, through GitHub (`@Widyasa`) and wait for a reply before disclosing details.

A vulnerability in a third-party package that PatchSense reports is handled by that package's maintainers and by OSV. PatchSense does not ship those advisories itself.
