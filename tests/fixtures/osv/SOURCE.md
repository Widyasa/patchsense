# OSV `querybatch` fixture

- Endpoint: `POST https://api.osv.dev/v1/querybatch`
- Retrieved: 2026-10-25
- Request body:

```json
{"queries":[{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.15"},{"package":{"ecosystem":"npm","name":"left-pad"},"version":"1.3.0"}]}
```

`querybatch_lodash.json` is the response body unchanged. The first result lists lodash advisories, including `GHSA-35jh-r3h4-6jhm`. The second result is empty (`left-pad` 1.3.0 had no vulns that day).

# OSV vulnerability document

- Endpoint: `GET https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm`
- Retrieved: 2026-10-25
- File: `vulns/GHSA-35jh-r3h4-6jhm.json` (response body unchanged)

The document aliases `CVE-2021-23337`, carries CVSS:3.1 vector `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, and fixes npm `lodash` in 4.17.21. It also lists other packages (`lodash-es`, RubyGems `lodash-rails`); those are not applied when the installed package is npm `lodash`.
