# CircleCI integration

Add the Docker Container Scanner to your CircleCI pipeline so every push is scanned and reports are available as pipeline artifacts.

## Prerequisites

- CircleCI project is connected to your VCS repository (GitHub, GitLab, or Bitbucket).
- The pipeline uses a Docker executor (e.g. `docker:24-cli`) or a `machine` executor — both have Docker available.
- Scanner image is reachable from the build: either public (`ghcr.io/beejak/docker-scanner:latest`) or in a private registry your pipeline can authenticate to.

## Overview

The example config defines two jobs in a `build-and-scan` workflow:

| Job | What it does |
|-----|-------------|
| `build` | Checks out the repo, builds `app:$CIRCLE_SHA1`, saves it to the workspace |
| `scan` | Loads the image, pulls the scanner, runs the scan, stores artifacts |

The `scan` job runs after `build` completes (`requires: [build]`), ensuring the image is always fresh.

## Step-by-step explanation

### 1. Executor — `docker:24-cli`

```yaml
executors:
  docker-cli:
    docker:
      - image: docker:24-cli
```

`docker:24-cli` is a minimal Alpine-based image with the Docker CLI installed. Combined with `setup_remote_docker`, CircleCI provisions a remote Docker daemon your steps can talk to. No sidecar service or privileged mode is needed.

If you prefer a full Linux VM (no DinD), swap the executor for:

```yaml
machine:
  image: ubuntu-2204:current
```

Remove the `setup_remote_docker` steps when using the machine executor — Docker is already running.

### 2. Image name from CircleCI environment variables

CircleCI exposes several built-in variables you can use to uniquely identify the image being built:

| Variable | Value |
|----------|-------|
| `$CIRCLE_SHA1` | Full Git commit SHA of the current build |
| `$CIRCLE_PROJECT_REPONAME` | Repository name (e.g. `my-app`) |
| `$CIRCLE_BRANCH` | Branch name (e.g. `main`) |
| `$CIRCLE_BUILD_NUM` | Unique build number within the project |

The example config tags the image as `app:$CIRCLE_SHA1`:

```yaml
environment:
  IMAGE_NAME: app:$CIRCLE_SHA1
```

A more descriptive tag combining the repo name and SHA:

```bash
IMAGE_NAME: "$CIRCLE_PROJECT_REPONAME:$CIRCLE_SHA1"
```

### 3. Passing the image between jobs — workspace

Jobs in CircleCI run in isolated environments; they cannot share a Docker daemon directly. The example saves the built image as a tar file and uses a **workspace** to share it:

```yaml
# In the build job:
- run:
    name: Save image to workspace
    command: |
      mkdir -p /tmp/docker-images
      docker save "$IMAGE_NAME" -o /tmp/docker-images/app.tar

- persist_to_workspace:
    root: /tmp
    paths:
      - docker-images

# In the scan job:
- attach_workspace:
    at: /tmp

- run:
    name: Load application image from workspace
    command: docker load -i /tmp/docker-images/app.tar
```

### 4. Running the scanner

```yaml
- run:
    name: Run container scan
    command: |
      docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v scan-reports:/reports \
        "$SCANNER_IMAGE" scan \
          --image "$IMAGE_NAME" \
          --output-dir /reports \
          --format sarif,markdown,html \
          --fail-on-severity CRITICAL,HIGH
```

Key flags:

| Flag | Effect |
|------|--------|
| `--format sarif,markdown,html` | Produces `report.sarif`, `report.md`, and `report.html` |
| `--fail-on-severity CRITICAL,HIGH` | Exits `1` if any matching finding is present; fails the pipeline |
| `--output-dir /reports` | Writes all report files into the mounted volume |

See [CLI reference](../cli-reference.md) for the full list of flags (`--severity`, `--offline`, `--baseline-image`, `--sbom`, `--check-runtime`, etc.).

### 5. Storing artifacts

Reports are copied from the Docker volume to the build host, then stored as CircleCI artifacts:

```yaml
- store_artifacts:
    path: /tmp/scan-reports
    destination: scan-reports
```

To view them:

1. Open the CircleCI dashboard and navigate to your project.
2. Click the **scan** job in the pipeline view.
3. Select the **Artifacts** tab.
4. Click any file (`report.sarif`, `report.md`, `report.html`) to download or view it.

### 6. Keeping artifacts after a failed scan

The scan step exits `1` when policy violations are found. To ensure reports are still uploaded when the build fails, the copy and `store_artifacts` steps use `when: always`:

```yaml
- run:
    name: Copy reports from Docker volume
    when: always
    command: ...

- store_artifacts:
    path: /tmp/scan-reports
    destination: scan-reports
```

The scanner's exit code is saved to a file and re-raised after the copy, so the job still fails as expected.

## Setting registry secrets

If your application image or the scanner image lives in a private registry, add credentials as **environment variables** in CircleCI — never hard-code them in the config.

1. Go to your CircleCI project.
2. Click **Project Settings** (gear icon).
3. Select **Environment Variables** from the left menu.
4. Click **Add Environment Variable** and add:
   - `REGISTRY_USERNAME` — your registry username or service account.
   - `REGISTRY_PASSWORD` — your registry password, token, or API key.

The example config reads these at runtime:

```yaml
- run:
    name: Log in to private registry (optional)
    command: |
      if [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ]; then
        echo "$REGISTRY_PASSWORD" | docker login \
          --username "$REGISTRY_USERNAME" \
          --password-stdin
      fi
```

For registries that need a hostname (e.g. AWS ECR, GCR, Azure ACR), pass it as a third environment variable and add it to the `docker login` command:

```bash
docker login "$REGISTRY_HOST" \
  --username "$REGISTRY_USERNAME" \
  --password-stdin <<< "$REGISTRY_PASSWORD"
```

Environment variables set in Project Settings are available to all jobs. For tighter scoping, use [CircleCI Contexts](https://circleci.com/docs/contexts/) to share secrets across multiple projects or restrict access by team.

## SARIF and CircleCI

CircleCI does not have a native Security tab that ingests SARIF files the way GitHub Code Scanning or GitLab's Security dashboard does. The recommended approach is:

1. **Store the SARIF as an artifact** (already done by `store_artifacts`) — reviewers can download and open it locally in any SARIF viewer (VS Code extension, GitHub Code Scanning offline upload, etc.).
2. **Post a Markdown summary as a comment** on your pull request using the CircleCI API or a third-party orb. The `report.md` produced by the scanner is designed to be human-readable and works well in PR comments. Example with `gh` CLI:

   ```yaml
   - run:
       name: Comment Markdown summary on PR (optional)
       when: always
       command: |
         if [ -n "$CIRCLE_PULL_REQUEST" ]; then
           PR_NUMBER=$(basename "$CIRCLE_PULL_REQUEST")
           gh pr comment "$PR_NUMBER" \
             --body-file /tmp/scan-reports/report.md \
             --repo "$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME"
         fi
   ```

   This requires a `GITHUB_TOKEN` environment variable with `pull-requests: write` permission.

## Example config

See [ci/circleci/config.example.yml](../../ci/circleci/config.example.yml) for the full, copy-paste-ready config.

Replace `ghcr.io/beejak/docker-scanner:latest` with your scanner image reference.
