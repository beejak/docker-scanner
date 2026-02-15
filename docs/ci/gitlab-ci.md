# GitLab CI integration

Add the Docker Container Scanner to your pipeline so merge requests are scanned and SARIF is shown in the Security dashboard.

## Prerequisites

- Job has Docker (e.g. `docker:24` with `docker:24-dind` service).
- Scanner image is available: build from this repo or pull from your registry.

## Steps

1. **Build your app image** in `before_script` or a previous stage.
2. **Run the scanner** in the job script; write reports to a directory (e.g. `reports/`).
3. **Declare SARIF artifact** with `reports: sast: reports/report.sarif` so GitLab shows results in the MR Security widget and Security dashboard.
4. **Archive report files** (optional) with `paths: [reports/]`.

## Example

See [ci/gitlab/job.example.yml](../../ci/gitlab/job.example.yml) for a full job example.

Replace `<IMAGE_NAME>` with your built image (e.g. `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA`).

## Registry auth

Use GitLab CI variables (`CI_REGISTRY_USER`, `CI_REGISTRY_PASSWORD`) or a job token to pull from the GitLab registry. For other registries, add variables and `docker login` in `before_script`.

## CLI reference

See [CLI reference](../cli-reference.md) for all flags (`--severity`, `--offline`, `--baseline-image`, etc.).
