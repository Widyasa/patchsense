# OSV `querybatch` fixture

- Endpoint: `POST https://api.osv.dev/v1/querybatch`
- Retrieved: 2026-10-25
- Request body:

```json
{"queries":[{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.15"},{"package":{"ecosystem":"npm","name":"left-pad"},"version":"1.3.0"}]}
```

`querybatch_lodash.json` is the response body unchanged. The first result lists lodash advisories, including `GHSA-35jh-r3h4-6jhm`. The second result is empty (`left-pad` 1.3.0 had no vulns that day).
