# GitLab CI

`templates/gitlab/patchsense.gitlab-ci.yml` scans lockfiles, stores the JSON and markdown reports, publishes a Dependency Scanning report, and updates one merge-request note when `GITLAB_TOKEN` is set.

## Include

Copy the template into the project and include it:

```yaml
include:
  - local: templates/gitlab/patchsense.gitlab-ci.yml
```

After the v0.1.1 GitHub Release exists, the same file can be included from the raw URL of that tag. The installer in `before_script` downloads `patchsense-installer.sh` from `Widyasa/patchsense` releases. The crates.io 0.1.0 publish does not upload that asset, so a pipeline that reaches the install step fails until v0.1.1. See the release checklist.

## Variables

| Variable | Required | Meaning |
| --- | --- | --- |
| `GITLAB_TOKEN` | For the MR note | Project access token, scope `api`, stored as a masked CI/CD variable. `CI_JOB_TOKEN` is not enough to write notes. |
| `CI_API_V4_URL` | Provided by GitLab | Used by `patchsense comment`. |
| `CI_PROJECT_ID` | Provided by GitLab | Used by `patchsense comment`. |
| `CI_MERGE_REQUEST_IID` | On merge request pipelines | Used by `patchsense comment`. |
| `PATCHSENSE_VERSION` | No | `latest`, `0.1.0`, or `v0.1.0`. A value without `v` gets that prefix. A value that already starts with `v` is used as the tag. |
| `PATCHSENSE_FAIL_ON` | No | `critical` (default), `review`, `any`, `never`, or a score 0–100. |
| `PATCHSENSE_PATH` | No | Directory or lockfile. Default `.`. |

The job runs on merge-request pipelines and on the default branch.

## Artifacts

`gl-dependency-scanning-report.json` is the GitLab Dependency Scanning report (schema 15.2.5). The vulnerability report UI needs GitLab Ultimate. On other tiers the file is still an artifact, next to `patchsense-report.json` and `patchsense-report.md`.

When both `CI_MERGE_REQUEST_IID` and `GITLAB_TOKEN` are set, the job runs `patchsense comment --provider gitlab`. A failed comment does not change the scan exit code.

## Manual check

This repository was not run on a GitLab project from this change. Widya runs one pipeline on a test project after the installer release exists and records the result.
