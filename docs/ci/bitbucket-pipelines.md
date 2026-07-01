# Bitbucket Pipelines integration

Add the Docker Container Scanner to your Bitbucket Pipelines config so every push is scanned and reports are stored as pipeline artifacts.

## Prerequisites

Before using [`ci/bitbucket/bitbucket-pipelines.yml`](../../ci/bitbucket/bitbucket-pipelines.yml), confirm the following.

### 1. Enable Pipelines for the repository

1. Go to **Repository settings → Pipelines → Settings**.
2. Toggle **Enable Pipelines** on.

### 2. Enable the Docker service

The pipeline config declares `docker` as a service in the `definitions` block, which gives each step access to a Docker daemon. No extra setup is required beyond having Pipelines enabled — Bitbucket provides the Docker service automatically.

If you need more memory for large image builds, increase the `memory` value under `definitions.services.docker` in the YAML (default is `3072` MB; Bitbucket enforces a per-step limit based on your plan).

### 3. Have a container registry (optional)

If you want to push the built image to a registry before scanning, you need a registry and credentials. Common choices:

- **Docker Hub** — `docker.io`
- **AWS ECR** — `<account>.dkr.ecr.<region>.amazonaws.com`
- **Google Artifact Registry** — `<region>-docker.pkg.dev`
- **Bitbucket's own OCI registry** — available on supported plans

If you are only scanning a locally built image and not pushing, you can remove the `docker login` and `docker push` commands from the script.

---

## Set Repository Variables

Repository Variables are the Bitbucket equivalent of GitHub Secrets or GitLab CI/CD variables. They are injected into every pipeline run as environment variables.

1. Go to **Repository settings → Pipelines → Repository variables**.
2. Add the following variables:

| Variable | Example value | Secured |
|---|---|---|
| `REGISTRY_URL` | `123456789.dkr.ecr.us-east-1.amazonaws.com` | No |
| `REGISTRY_USERNAME` | `AWS` | No |
| `REGISTRY_PASSWORD` | `<secret>` | **Yes** |

Mark `REGISTRY_PASSWORD` (and any other secrets) as **Secured** so the value is masked in build logs and is not exposed to pull requests from forks.

### Bitbucket-injected variables

These are always available without configuration:

| Variable | Value |
|---|---|
| `$BITBUCKET_REPO_SLUG` | The repository slug (used as the image name) |
| `$BITBUCKET_COMMIT` | Full commit SHA |
| `$BITBUCKET_BRANCH` | Current branch name |
| `$BITBUCKET_BUILD_NUMBER` | Incrementing build number |

---

## Pipelines in this config

### `default` pipeline

Runs automatically on every push to any branch. Steps:

1. Log in to your container registry.
2. Build the application image tagged `$BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT`.
3. Build the scanner image.
4. Run the scanner with `--format sarif,markdown` and `--fail-on-severity CRITICAL,HIGH`.
5. Store `report.sarif` and `report.md` as pipeline artifacts.

### `custom: scan` pipeline

Triggered manually from the **Pipelines** UI (Run pipeline → Select pipeline → `scan`) or via the [Bitbucket API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/). Useful for on-demand or scheduled scans without a code push.

To schedule a nightly scan using the Bitbucket API:

```bash
curl -s -X POST \
  -u "$BITBUCKET_USERNAME:$BITBUCKET_APP_PASSWORD" \
  "https://api.bitbucket.org/2.0/repositories/$WORKSPACE/$REPO_SLUG/pipelines/" \
  -H "Content-Type: application/json" \
  -d '{"target":{"type":"pipeline_ref_target","ref_type":"branch","ref_name":"main","selector":{"type":"custom","pattern":"scan"}}}'
```

---

## View artifacts

After a pipeline run completes:

1. Go to **Pipelines** → click on the specific build.
2. Click the **Artifacts** tab (or scroll to the step that produced artifacts).
3. Download `report.sarif` or `report.md` directly from the browser.

Artifacts are also accessible via the Bitbucket API:

```bash
curl -s -u "$BITBUCKET_USERNAME:$BITBUCKET_APP_PASSWORD" \
  "https://api.bitbucket.org/2.0/repositories/$WORKSPACE/$REPO_SLUG/pipelines/$PIPELINE_UUID/steps/$STEP_UUID/artifacts"
```

---

## SARIF reports

Bitbucket Pipelines does not have a native SARIF Security tab (unlike GitHub's Code Scanning). The `report.sarif` file is stored as a pipeline artifact (see above). Options for viewing findings:

### Download and view locally

Download `report.sarif` from the pipeline artifacts and open it in a SARIF-aware editor:

- **VS Code** with the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- **GitHub** — upload to a GitHub repository's Code Scanning via the API if you mirror there

### Upload to an external security dashboard

If your organisation uses a security platform that accepts SARIF (e.g. Snyk, Semgrep AppSec, Defender for DevOps), add a step to the pipeline that posts the SARIF file to that platform's API after the scan step.

### Parse the Markdown report

`report.md` is a human-readable summary of findings. It renders natively in Bitbucket if you commit it or view it as an artifact, and can be posted as a pull request comment using the Bitbucket Reports API.

---

## CLI reference

See [CLI reference](../cli-reference.md) for all scanner flags (`--severity`, `--offline`, `--baseline-image`, `--sbom`, etc.).
