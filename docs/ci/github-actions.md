# GitHub Actions integration

Add the Docker Container Scanner to your GitHub Actions workflow so every push and pull request is scanned, findings are surfaced in the Security tab as Code Scanning alerts, and full reports are available as downloadable artifacts.

## Prerequisites

- **Runner**: the workflow must run on a runner that has Docker installed. `ubuntu-latest` (GitHub-hosted) satisfies this out of the box.
- **Docker socket**: the scanner runs as a container and needs to reach the host Docker daemon via `/var/run/docker.sock`. GitHub-hosted Ubuntu runners expose this socket without any additional configuration.
- **Permissions**: the job needs `security-events: write` to upload SARIF to GitHub Code Scanning, and `contents: read` to check out the repository. If you are authenticating to GHCR with the built-in `GITHUB_TOKEN`, you also need `packages: read` (or `packages: write` if you are pushing images).
- **Scanner image**: either build the scanner from this repository (shown in the example below) or pull a published image from `ghcr.io/beejak/docker-scanner:latest`.

## Overview

The example workflow defines a single job, `scan`, with the following steps:

| Step | What it does |
|------|-------------|
| Checkout | Clones the repository so the `Dockerfile` is available to build from |
| Build application image | Runs `docker build` and tags the result with the commit SHA |
| Build scanner image | Builds the scanner image once; reused across all subsequent steps |
| Create reports directory | Creates the host-side directory that will be bind-mounted into the scanner |
| Run container scan | Executes the scan, writes SARIF, Markdown, HTML, CSV, and a CycloneDX SBOM |
| Upload SARIF | Sends `report.sarif` to GitHub Code Scanning; runs even after a policy failure |
| Upload artifact | Packages every report file as a downloadable workflow artifact |

## Trigger events

The example workflow responds to three event types:

```yaml
on:
  push:
    branches: ["main", "master"]
  pull_request:
  schedule:
    - cron: "0 2 * * *"
```

| Event | When it fires | Why it is useful |
|-------|--------------|-----------------|
| `push` | On every commit merged to `main` or `master` | Keeps the Security tab up to date with the state of your default branch |
| `pull_request` | On every PR opened, synchronised, or re-opened | Blocks merges when new vulnerabilities are introduced |
| `schedule` | Nightly at 02:00 UTC | Catches new CVEs published to the vulnerability database between code changes |

For other branch patterns, adjust the `branches` filter or replace it with `branches-ignore`.

## GitHub built-in variables

The workflow uses several expression contexts that GitHub populates automatically — no configuration required:

| Expression | Example value | Used for |
|-----------|--------------|---------|
| `github.sha` | `a3f9c1d…` | Unique image tag per commit; ensures the scan always targets the exact build being reviewed |
| `github.repository` | `myorg/my-app` | Constructing GHCR image references (`ghcr.io/${{ github.repository }}:latest`) |
| `github.ref_name` | `main` or `feature/foo` | Tagging images with a human-readable branch name in addition to the SHA |
| `github.workspace` | `/home/runner/work/my-app/my-app` | Absolute path used for bind-mounting the reports directory |
| `github.event_name` | `push`, `pull_request`, `schedule` | Conditionally skipping steps that only make sense on certain trigger types |

## Image reference passing between steps

Unlike CircleCI, where jobs run in fully isolated environments and must exchange Docker images through a workspace tar file, all steps within a single GitHub Actions job share the **same Docker daemon**. An image built in step 2 is immediately visible to every subsequent step in the same job without any export or import step.

This means:

```yaml
- name: Build application image
  run: docker build -t ${{ env.IMAGE_NAME }} .

# No docker save / docker load needed. The image is already in the daemon.
- name: Run container scan
  run: |
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      ...
      ${{ env.SCANNER_IMAGE }} scan --image ${{ env.IMAGE_NAME }} ...
```

The scanner container accesses the application image through the shared socket — it calls `docker inspect` and pulls layer data from the same daemon that built it. No intermediate artifact or registry push is required.

## Full annotated workflow

The workflow below is a copy-paste-ready starting point. Inline comments explain every non-obvious decision.

```yaml
# GitHub Actions — Container Security Scan
#
# What this does:
#   1. Builds your application image
#   2. Builds the scanner image (Trivy + CLI + Web UI server)
#   3. Runs a full scan: vulnerability detection, runc advisory, SBOM generation
#   4. Uploads SARIF to GitHub Security tab (Code Scanning alerts)
#   5. Publishes all reports + SBOM as a pipeline artifact
#   6. Fails the build if any CRITICAL or HIGH findings are present
#
# Customise IMAGE_NAME to match your app image.
# Adjust --fail-on-severity to your risk tolerance.

name: Container Security Scan

on:
  push:
    branches: ["main", "master"]
  pull_request:
  schedule:
    # Nightly re-scan so new CVEs in the DB are caught even without a code change.
    - cron: "0 2 * * *"

jobs:
  scan:
    name: Vulnerability scan
    runs-on: ubuntu-latest

    permissions:
      contents: read
      # Required to upload SARIF results to GitHub Code Scanning.
      security-events: write

    env:
      # Tag the image with the commit SHA so each run scans a distinct, traceable image.
      IMAGE_NAME: app:${{ github.sha }}
      SCANNER_IMAGE: scanner:latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      # Build the application image you want to scan.
      - name: Build application image
        run: docker build -t ${{ env.IMAGE_NAME }} .

      # Pull the published scanner image from GHCR. No source code required.
      - name: Pull scanner image
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker pull ghcr.io/beejak/docker-scanner:latest
          docker tag ghcr.io/beejak/docker-scanner:latest ${{ env.SCANNER_IMAGE }}
        # To build the scanner from source instead (e.g. in a fork or dev workflow),
        # replace the run block above with:
        #   run: docker build -t ${{ env.SCANNER_IMAGE }} /path/to/docker-scanner

      - name: Create reports directory
        run: mkdir -p reports

      # Full scan: all formats + runc advisory + SBOM + fail-on policy.
      #
      # Flag reference:
      #   --format sarif,markdown,html,csv
      #       Writes report.sarif, report.md, report.html, report.csv to /reports.
      #   --check-runtime
      #       Checks the runner's runc binary for known container-escape CVEs.
      #   --sbom
      #       Generates a CycloneDX SBOM at reports/report.cdx.json.
      #   --fail-on-severity CRITICAL,HIGH
      #       Exits 1 if any matching finding is present, failing the step.
      #       Downstream steps use 'if: always()' so they still run after a failure.
      - name: Run container scan
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v ${{ github.workspace }}/reports:/reports \
            ${{ env.SCANNER_IMAGE }} scan \
              --image ${{ env.IMAGE_NAME }} \
              --output-dir /reports \
              --format sarif,markdown,html,csv \
              --check-runtime \
              --sbom \
              --fail-on-severity CRITICAL,HIGH

      # Upload SARIF so findings appear in the GitHub Security → Code Scanning tab.
      #
      # 'if: always()' is required here. Without it, GitHub Actions skips this step
      # whenever a previous step fails — which is exactly what happens when
      # --fail-on-severity detects violations and exits 1. The SARIF file exists on
      # disk even after a policy failure, so 'always()' ensures it is always uploaded.
      #
      # The 'category' field namespaces the results inside Code Scanning. If you run
      # multiple scans in the same repository (e.g. one for each service), give each
      # a distinct category so their alerts do not overwrite each other.
      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/report.sarif
          category: container-scan

      # Publish all reports + SBOM as a downloadable artifact.
      #
      # 'if: always()' is needed for the same reason as the SARIF upload — reports
      # must be preserved even when the scan step exits 1 so teams can review findings.
      # Naming the artifact with the SHA makes it easy to correlate with the commit.
      - name: Upload scan reports artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scan-reports-${{ github.sha }}
          path: reports/
          retention-days: 30
```

## The `--fail-on-severity` gate

When `--fail-on-severity CRITICAL,HIGH` is passed, the scanner exits with code `1` if any finding at those severity levels is present. GitHub Actions interprets a non-zero exit code as a step failure and marks the job as failed.

This means **the two steps that follow the scan step — SARIF upload and artifact upload — would be skipped by default**, because GitHub Actions skips steps after a failure unless instructed otherwise. To prevent this, both steps carry:

```yaml
if: always()
```

`always()` is an expression that evaluates to `true` regardless of the outcome of previous steps, including failures and cancellations. It is the correct choice here because:

- The SARIF file and report files exist on disk even when findings are present.
- Uploading them is the primary way to communicate *why* the build failed.
- Using `if: failure()` alone would skip the upload on a successful scan.

Do **not** use `continue-on-error: true` on the scan step itself. That would prevent the job from being marked as failed and would allow the pull request to be merged without addressing policy violations.

## SARIF upload and Code Scanning

The `github/codeql-action/upload-sarif@v3` action sends `report.sarif` to GitHub's Code Scanning API. After upload, findings appear under **Security → Code Scanning** in your repository.

Key parameters:

| Parameter | Value in example | Notes |
|-----------|-----------------|-------|
| `sarif_file` | `reports/report.sarif` | Path relative to `github.workspace`; must match `--output-dir` |
| `category` | `container-scan` | Namespaces alerts; use a unique value per scanner/service |

The `security-events: write` permission in the job's `permissions` block is mandatory. Without it the upload call returns HTTP 403 and the step fails with a permission error.

Once SARIF is uploaded, GitHub links each alert to the relevant file and line when the SARIF includes region information. The scanner produces region-annotated SARIF where applicable.

## Artifact upload

`actions/upload-artifact@v4` collects everything in `reports/` — SARIF, Markdown, HTML, CSV, and the CycloneDX SBOM — and makes them available from the **Actions → workflow run → Artifacts** panel.

```yaml
- name: Upload scan reports artifact
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: scan-reports-${{ github.sha }}
    path: reports/
    retention-days: 30
```

The `retention-days: 30` setting keeps artifacts for 30 days. Adjust this to match your compliance requirements. The artifact name includes `github.sha` so each run produces a distinct, non-colliding artifact that is easy to trace back to the triggering commit.

To download from the CLI:

```bash
gh run download <run-id> --name scan-reports-<sha>
```

## Secrets setup

For private registries — whether for your application image or for a private scanner image — store credentials as encrypted secrets rather than hard-coding them in the workflow.

1. In your repository, go to **Settings → Secrets and variables → Actions**.
2. Click **New repository secret**.
3. Add the secrets your workflow needs, for example:
   - `REGISTRY_USERNAME` — your registry username or service account name.
   - `REGISTRY_PASSWORD` — your registry password, token, or API key.

Reference secrets in the workflow via the `secrets` context:

```yaml
- name: Log in to private registry
  run: |
    echo "${{ secrets.REGISTRY_PASSWORD }}" | docker login "$REGISTRY_HOST" \
      --username "${{ secrets.REGISTRY_USERNAME }}" \
      --password-stdin
```

Secrets are masked in workflow logs. They are available to all jobs in the repository by default; for tighter scoping, use [GitHub Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) to restrict secret access to specific branches or require manual approval.

## GHCR authentication

GitHub Container Registry (`ghcr.io`) can be accessed in two ways:

### `GITHUB_TOKEN` (recommended)

`GITHUB_TOKEN` is automatically provisioned by GitHub Actions for every workflow run. It requires no setup, rotates automatically, and never leaves the Actions context.

```yaml
- name: Log in to GHCR
  run: |
    echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io \
      --username ${{ github.actor }} \
      --password-stdin
```

Grant `packages: read` (or `packages: write` if pushing) in the job's `permissions` block:

```yaml
permissions:
  contents: read
  security-events: write
  packages: read
```

`GITHUB_TOKEN` can only access packages belonging to the same repository or organisation. If the scanner image lives in a different organisation's GHCR namespace, use a PAT instead.

### Personal Access Token (PAT)

If you need cross-organisation access or your runner environment cannot use `GITHUB_TOKEN`, create a Classic PAT with the `read:packages` scope (and `write:packages` if pushing), store it as a repository secret, and reference it in the login step:

```yaml
- name: Log in to GHCR with PAT
  run: |
    echo "${{ secrets.GHCR_PAT }}" | docker login ghcr.io \
      --username ${{ secrets.GHCR_USERNAME }} \
      --password-stdin
```

Fine-grained PATs do not support package registry operations; use Classic PATs for GHCR. See [GitHub's PAT documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) for current scope details.

## Setting registry secrets

If your application image lives in a non-GHCR private registry (AWS ECR, GCR, Azure ACR, Docker Hub private), the login step is the same pattern:

```yaml
- name: Log in to private registry (optional)
  run: |
    if [ -n "${{ secrets.REGISTRY_USERNAME }}" ]; then
      echo "${{ secrets.REGISTRY_PASSWORD }}" | docker login "${{ secrets.REGISTRY_HOST }}" \
        --username "${{ secrets.REGISTRY_USERNAME }}" \
        --password-stdin
    fi
```

For cloud-native authentication (AWS OIDC, GCP Workload Identity, Azure Managed Identity), use the provider's official action instead of static credentials — these approaches eliminate long-lived secrets from your repository entirely.

## CLI reference

See [CLI reference](../cli-reference.md) for the full list of scanner flags, including `--severity`, `--offline`, `--baseline-image`, `--sbom`, `--check-runtime`, and output format options.
