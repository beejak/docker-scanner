# Azure DevOps Pipelines integration

Add the Docker Container Scanner to your Azure DevOps pipeline so every push is scanned, SARIF results appear in the Security tab, and full reports are available as pipeline artifacts.

## Prerequisites

- **Microsoft-hosted agent** — the examples below use `ubuntu-latest`, which ships with Docker pre-installed. No additional setup is needed for Docker itself.
- **Docker task** — the `Docker@2` task is built into Azure Pipelines and requires no extra installation.
- **`PublishSecurityAnalysisResults@1` extension** — SARIF publishing to the Security tab requires the [Microsoft Security DevOps](https://marketplace.visualstudio.com/items?itemName=ms-securitydevops.microsoft-security-devops-azdevops) extension (free) installed in your Azure DevOps organisation. Without it, SARIF must be published as a plain artifact instead (see [SARIF publishing](#sarif-publishing)).
- **Scanner image reachable from the agent** — either the public image (`ghcr.io/beejak/docker-scanner:latest`) or one pushed to a private registry your pipeline can authenticate to.

## Overview

The example pipeline covers the following steps in order:

| Step | Task / command | What it does |
|------|---------------|--------------|
| Build application image | `Docker@2` | Builds your app Dockerfile and tags the image with the build ID |
| Build or pull scanner image | `script` | Builds the scanner from source, or pulls a pre-published image |
| Create reports directory | `script` | Creates `$(Build.ArtifactStagingDirectory)/reports` |
| Run container scan | `script` | Runs the scanner container; writes SARIF, Markdown, HTML, and CSV reports |
| Publish SARIF to Security tab | `PublishSecurityAnalysisResults@1` | Surfaces findings in the pipeline Security tab |
| Publish all reports as artifact | `PublishPipelineArtifact@1` | Makes every report file downloadable from the pipeline run |

## Built-in variables

Azure Pipelines exposes these predefined variables, which the example pipeline uses to produce unique, traceable image names and paths:

| Variable | Example value | Used for |
|----------|--------------|---------|
| `Build.BuildId` | `42` | Unique build number — used as the image tag |
| `Build.SourceVersion` | `a3f1b9c2…` | Full Git commit SHA of the triggering commit |
| `Build.Repository.Name` | `my-app` | Repository name — useful for registry path construction |
| `Build.ArtifactStagingDirectory` | `/home/vsts/work/1/a` | Writable staging area; contents are uploaded automatically |
| `Build.SourceBranchName` | `main` | Branch name (short form, without `refs/heads/`) |

Reference any variable in YAML with `$(Variable.Name)`.

## Full pipeline

Save this file as `azure-pipelines.yml` at the root of your repository. Inline comments explain each section.

```yaml
# azure-pipelines.yml
#
# Builds your application image, runs a full container security scan, publishes
# SARIF to the Azure DevOps Security tab, and uploads all reports as a pipeline
# artifact. The build fails if any CRITICAL or HIGH vulnerability is found.

trigger:
  branches:
    include:
      - main
      - master

pr:
  branches:
    include:
      - main
      - master

# Optional: re-scan nightly even without a new commit, to catch newly published CVEs.
schedules:
  - cron: "0 2 * * *"
    displayName: Nightly re-scan
    branches:
      include: [main]
    always: true

pool:
  vmImage: ubuntu-latest   # Microsoft-hosted; Docker is pre-installed.

variables:
  # Image name incorporates the build ID so every run produces a unique tag.
  imageName: "app:$(Build.BuildId)"

  # Use the public scanner image, or substitute a reference to your private registry.
  scannerImage: "ghcr.io/beejak/docker-scanner:latest"

  # All report files land here; Azure Pipelines stages this directory for artifact upload.
  reportsDir: "$(Build.ArtifactStagingDirectory)/reports"

steps:
  # ── 1. Build your application image ──────────────────────────────────────────
  # Docker@2 wraps `docker build` and optionally pushes to a registry.
  # Remove `containerRegistry` and `repository` if you do not want to push.
  - task: Docker@2
    displayName: Build application image
    inputs:
      command: build
      dockerfile: "**/Dockerfile"        # Glob — adjust if your Dockerfile is not at repo root.
      tags: "$(Build.BuildId)"
      arguments: "-t $(imageName)"
      # containerRegistry: my-acr-service-connection   # Uncomment to push to ACR after build.
      # repository: $(Build.Repository.Name)

  # ── 2. Pull or build the scanner image ───────────────────────────────────────
  # Option A (shown): pull the pre-published scanner image from GHCR.
  # Option B: build the scanner from source — replace the script body with:
  #   docker build -t $(scannerImage) .
  - script: docker pull $(scannerImage)
    displayName: Pull scanner image

  # ── 3. Create the reports output directory ────────────────────────────────────
  - script: mkdir -p $(reportsDir)
    displayName: Create reports directory

  # ── 4. Run the container scan ─────────────────────────────────────────────────
  # The scanner runs as a container with access to the host Docker socket so it
  # can inspect the image that was just built. Reports are written to $(reportsDir)
  # via a bind mount.
  #
  # --format sarif,markdown,html,csv  Writes report.sarif, report.md, report.html,
  #                                   report.csv to /reports.
  # --check-runtime                   Checks the running runc/containerd version
  #                                   for known advisories.
  # --sbom                            Generates a CycloneDX SBOM alongside reports.
  # --fail-on-severity CRITICAL,HIGH  Exits 1 if any matching finding is present,
  #                                   which fails this pipeline step.
  #
  # To collect reports even when the policy gate trips, add:
  #   continueOnError: true
  # and re-raise the exit code explicitly (see "Severity gate" section below).
  - script: |
      docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v $(reportsDir):/reports \
        $(scannerImage) scan \
          --image $(imageName) \
          --output-dir /reports \
          --format sarif,markdown,html,csv \
          --check-runtime \
          --sbom \
          --fail-on-severity CRITICAL,HIGH
    displayName: Run container scan

  # ── 5. Publish SARIF to the Security tab ─────────────────────────────────────
  # Requires the Microsoft Security DevOps extension in your organisation.
  # condition: always() ensures SARIF is published even when the scan step fails.
  - task: PublishSecurityAnalysisResults@1
    displayName: Publish SARIF to Security tab
    condition: always()
    inputs:
      SarifFile: "$(reportsDir)/report.sarif"

  # ── 6. Publish all reports as a pipeline artifact ────────────────────────────
  # Makes report.sarif, report.md, report.html, report.csv, and the SBOM available
  # on the pipeline run's Artifacts tab.
  - task: PublishPipelineArtifact@1
    displayName: Publish scan reports
    condition: always()
    inputs:
      targetPath: "$(reportsDir)"
      artifactName: scan-reports
      publishLocation: pipeline
```

## ACR authentication

### Recommended: service connection

A Docker Registry service connection stores credentials in Azure DevOps and never exposes them as plain text in pipeline logs or YAML.

1. In your Azure DevOps project, go to **Project Settings** > **Service connections**.
2. Click **New service connection** > **Docker Registry**.
3. Choose **Azure Container Registry**, select your subscription, and pick your ACR instance.
4. Name the connection (e.g. `my-acr-connection`) and click **Save**.

Reference the service connection in the `Docker@2` task:

```yaml
- task: Docker@2
  displayName: Build and push application image
  inputs:
    command: buildAndPush
    containerRegistry: my-acr-connection   # Service connection name.
    repository: $(Build.Repository.Name)
    dockerfile: "**/Dockerfile"
    tags: |
      $(Build.BuildId)
      $(Build.SourceBranchName)
```

To log in to ACR before a plain `docker run` (e.g. to pull the scanner from ACR):

```yaml
- task: Docker@2
  displayName: Log in to ACR
  inputs:
    command: login
    containerRegistry: my-acr-connection
```

### Alternative: environment variables

If a service connection is not an option, pass credentials as pipeline variables (see [Secrets](#secrets-library-variable-groups-and-pipeline-variables)) and log in with the Docker CLI:

```yaml
- script: |
    echo "$(ACR_PASSWORD)" | docker login \
      $(ACR_LOGIN_SERVER) \
      --username $(ACR_USERNAME) \
      --password-stdin
  displayName: Log in to ACR (env var approach)
  env:
    ACR_PASSWORD: $(ACR_PASSWORD)   # Marked secret — injected at runtime, not echoed.
```

`$(ACR_LOGIN_SERVER)` is the hostname of your registry, e.g. `myregistry.azurecr.io`.

The service connection approach is strongly preferred because Azure DevOps rotates and manages the token automatically and the secret never appears in the YAML file.

## Secrets: Library Variable Groups and Pipeline Variables

Never hard-code registry passwords, API tokens, or other secrets in `azure-pipelines.yml`. Azure DevOps provides two mechanisms for injecting them safely.

### Library Variable Groups

Variable Groups are defined once and linked to multiple pipelines.

1. Go to **Pipelines** > **Library** > **+ Variable group**.
2. Add variables (e.g. `ACR_USERNAME`, `ACR_PASSWORD`, `SCANNER_TOKEN`).
3. Click the lock icon next to sensitive values to mark them as secrets — they are encrypted at rest and masked in logs.
4. Link the group to your pipeline with the `group` key:

```yaml
variables:
  - group: docker-scanner-secrets   # Variable Group name.
  - name: imageName
    value: "app:$(Build.BuildId)"
  - name: reportsDir
    value: "$(Build.ArtifactStagingDirectory)/reports"
```

Secrets from the group are available as `$(ACR_PASSWORD)` throughout the pipeline but are never echoed to logs.

### Pipeline Variables

For per-pipeline secrets, define them directly on the pipeline:

1. Open your pipeline in Azure DevOps.
2. Click **Edit** > **Variables** (top right).
3. Add the variable name and value, and check **Keep this value secret**.

Secret pipeline variables must be explicitly mapped into `script` steps via the `env` key — Azure Pipelines does not inject them automatically to prevent accidental exposure:

```yaml
- script: |
    echo "$(REGISTRY_PASSWORD)" | docker login \
      --username $(REGISTRY_USERNAME) \
      --password-stdin
  displayName: Registry login
  env:
    REGISTRY_PASSWORD: $(REGISTRY_PASSWORD)
```

## SARIF publishing

### Via `PublishSecurityAnalysisResults@1` (recommended)

The `PublishSecurityAnalysisResults@1` task, provided by the [Microsoft Security DevOps](https://marketplace.visualstudio.com/items?itemName=ms-securitydevops.microsoft-security-devops-azdevops) extension, uploads SARIF to the pipeline's **Security** tab where findings are displayed inline with code references.

**Extension requirement:** an Azure DevOps organisation administrator must install the extension once from the Visual Studio Marketplace. If the task is not available, the pipeline will fail with `##[error] A task is missing`. Ask your organisation admin to install it, or use the fallback below.

```yaml
- task: PublishSecurityAnalysisResults@1
  displayName: Publish SARIF to Security tab
  condition: always()   # Run even when the scan step exits non-zero.
  inputs:
    SarifFile: "$(reportsDir)/report.sarif"
```

`condition: always()` is important: without it, a failed scan step (due to `--fail-on-severity`) would skip SARIF publishing, leaving the Security tab empty.

### Fallback: artifact upload

If the extension is not available, publish the SARIF file as a pipeline artifact instead:

```yaml
- task: PublishPipelineArtifact@1
  displayName: Publish SARIF as artifact (fallback)
  condition: always()
  inputs:
    targetPath: "$(reportsDir)/report.sarif"
    artifactName: sarif-report
    publishLocation: pipeline
```

Reviewers can download `report.sarif` from the **Artifacts** tab of the pipeline run and open it in any SARIF viewer (VS Code SARIF extension, GitHub Code Scanning offline upload, etc.).

## Severity gate and exit code behaviour

The `--fail-on-severity` flag controls whether the scan step fails the build.

| Value | Effect |
|-------|--------|
| `--fail-on-severity CRITICAL` | Exits `1` only when CRITICAL findings are present |
| `--fail-on-severity CRITICAL,HIGH` | Exits `1` if CRITICAL or HIGH findings are present |
| _(flag omitted)_ | Always exits `0`; build continues regardless of findings |

When the scanner exits `1`, Azure Pipelines marks the step as failed and the pipeline run as failed by default. Subsequent steps do not run unless they carry `condition: always()` or `condition: succeededOrFailed()`.

### Collecting reports on failure

To ensure reports and SARIF are published even when the gate trips, set `continueOnError: true` on the scan step and re-raise the exit code afterward:

```yaml
- script: |
    docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v $(reportsDir):/reports \
      $(scannerImage) scan \
        --image $(imageName) \
        --output-dir /reports \
        --format sarif,markdown,html,csv \
        --fail-on-severity CRITICAL,HIGH
    echo "##vso[task.setvariable variable=SCAN_EXIT_CODE]$?"
  displayName: Run container scan
  continueOnError: true   # Don't halt; let publish steps run first.

# ... PublishSecurityAnalysisResults and PublishPipelineArtifact steps here ...

- script: |
    if [ "$(SCAN_EXIT_CODE)" != "0" ]; then
      echo "##[error] Scanner found CRITICAL/HIGH vulnerabilities. Failing the build."
      exit 1
    fi
  displayName: Enforce severity gate
  condition: always()
```

This pattern lets `PublishSecurityAnalysisResults@1` and `PublishPipelineArtifact@1` always run, then re-raises the failure so the pipeline run is still marked as failed.

## CLI reference

For the full list of scanner flags — including `--severity`, `--offline`, `--baseline-image`, `--sbom`, `--check-runtime`, and output format options — see [CLI reference](../cli-reference.md).
