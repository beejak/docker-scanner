# GitLab CI/CD integration

Add the Docker Container Scanner to your GitLab pipeline so every push and merge request is scanned, SARIF findings appear in the Security dashboard, and policy gates block merges when critical vulnerabilities are present.

## Prerequisites

- **Docker-in-Docker runner.** Your GitLab runner must be configured with the `docker` executor and must be able to run privileged containers. The `docker:24-dind` service (or `docker:26-dind`) acts as the Docker daemon inside the pipeline job. Runners registered with `--executor docker --docker-privileged` satisfy this requirement; shared runners on GitLab.com already do.
- **`docker:24-dind` service.** Each job that builds or pulls images must declare the DinD service so a Docker daemon is available during the script phase.
- **`DOCKER_TLS_CERTDIR` set to `"/certs"`**. GitLab's official DinD images use mutual TLS between the client and daemon by default. Setting this variable to `/certs` tells both containers (the job image and the service) to write and read TLS certificates from the same shared path. Leaving it unset falls back to an unencrypted socket and produces connection errors on recent images.
- **Scanner image reachable from the build.** Build it from the repo (`docker build`) or pull a pre-published copy from your registry. The example below builds it inline.

## GitLab CI/CD built-in variables

GitLab injects the following variables automatically into every job. You do not need to declare them.

| Variable | Example value | Purpose |
|---|---|---|
| `CI_COMMIT_SHA` | `a1b2c3d4…` (40 chars) | Full SHA of the commit that triggered the pipeline |
| `CI_REGISTRY_IMAGE` | `registry.gitlab.com/my-group/my-app` | Base path for images in the project's Container Registry |
| `CI_REGISTRY` | `registry.gitlab.com` | Hostname of the GitLab Container Registry |
| `CI_REGISTRY_USER` | `gitlab-ci-token` | Short-lived username for authenticating to `CI_REGISTRY` |
| `CI_REGISTRY_PASSWORD` | *(masked job token)* | Short-lived password matching `CI_REGISTRY_USER`; rotated each pipeline |
| `CI_PROJECT_NAME` | `my-app` | Repository name; useful for tagging images or naming reports |

## Image ref construction and why SHA tags are preferred

A tag like `latest` or `main` is mutable — it can point to a different image layer between the `build` and `scan` jobs, undermining the guarantee that you scanned exactly what you built. Using the commit SHA produces an immutable, globally unique tag:

```bash
IMAGE_NAME: "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"
# e.g. registry.gitlab.com/acme/my-app:a1b2c3d4e5f6...
```

This means:

- The `build` job pushes `…:a1b2c3d4`.
- The `scan` job pulls `…:a1b2c3d4` — guaranteed to be the same layers, regardless of any concurrent pushes on other branches.
- Audit logs, SARIF reports, and the Security dashboard all reference the exact digest that was scanned.

You can additionally push a human-readable tag (e.g. `…:main`) after the SHA-tagged push without losing immutability for the scan.

## Full annotated `.gitlab-ci.yml`

The pipeline below defines two stages: `build` (compile and push the image) and `test` (pull, scan, publish results). Copy it to the root of your repository and adjust the variables at the top.

```yaml
# .gitlab-ci.yml

# ── Global variables ─────────────────────────────────────────────────────────
variables:
  # Immutable image ref: registry path + commit SHA.
  IMAGE_NAME: "${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}"

  # Tag for the scanner image built from this repo.
  # Replace with a pull reference if you publish the scanner separately,
  # e.g. "ghcr.io/beejak/docker-scanner:latest"
  SCANNER_IMAGE: "scanner:latest"

  # Required for Docker-in-Docker TLS handshake.
  # Both the job container and the dind service read/write certs here.
  DOCKER_TLS_CERTDIR: "/certs"

stages:
  - build
  - test

# ── Build application image ──────────────────────────────────────────────────
build:
  stage: build
  image: docker:26
  services:
    - docker:26-dind          # Docker daemon sidecar; TLS-secured via DOCKER_TLS_CERTDIR
  before_script:
    # Authenticate to the GitLab Container Registry using the auto-injected
    # short-lived job token. CI_REGISTRY_USER and CI_REGISTRY_PASSWORD are
    # rotated each pipeline run — no manual secret management required.
    - echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY"
        --username "$CI_REGISTRY_USER" --password-stdin
  script:
    # Build the application image and tag it with the immutable SHA ref.
    - docker build -t "$IMAGE_NAME" .
    # Push to the GitLab Container Registry so the scan job can pull it.
    - docker push "$IMAGE_NAME"
  rules:
    # Run on branch pushes and merge request pipelines.
    - if: $CI_COMMIT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"

# ── Container security scan ──────────────────────────────────────────────────
container-scan:
  stage: test
  image: docker:26
  services:
    - docker:26-dind
  # Wait for the build job to succeed before starting.
  needs: [build]
  before_script:
    # Re-authenticate so this job can pull the image pushed by the build job.
    - echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY"
        --username "$CI_REGISTRY_USER" --password-stdin
  script:
    # Pull the exact image that was just built.
    - docker pull "$IMAGE_NAME"

    # Build the scanner image from source.
    # If you publish the scanner separately, replace this with:
    #   docker pull "$SCANNER_IMAGE"
    - docker build -t "$SCANNER_IMAGE" .

    # Create the reports directory on the runner host.
    - mkdir -p reports

    # Run the full scan. Key flags explained below.
    - |
      docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$PWD/reports:/reports" \
        "$SCANNER_IMAGE" scan \
          --image "$IMAGE_NAME" \
          --output-dir /reports \
          --format sarif,markdown,html,csv \
          --check-runtime \
          --sbom \
          --fail-on-severity CRITICAL,HIGH

  artifacts:
    # Upload artifacts even when the scan job fails (i.e. when findings are
    # present). This ensures reports are always available for review.
    when: always
    expire_in: 30 days

    reports:
      # Tells GitLab to parse the SARIF file and surface findings in:
      #   • the Security dashboard (project-level summary)
      #   • the MR Security widget (diff-level view on merge requests)
      container_scanning: reports/report.sarif

    paths:
      # Also store all report files as downloadable job artifacts.
      - reports/

  rules:
    - if: $CI_COMMIT_BRANCH
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### Scan flags explained

| Flag | Effect |
|---|---|
| `--format sarif,markdown,html,csv` | Writes `report.sarif`, `report.md`, `report.html`, and `report.csv` to `--output-dir` |
| `--check-runtime` | Runs an additional advisory check on the container runtime (runc/containerd) |
| `--sbom` | Generates a Software Bill of Materials alongside the vulnerability report |
| `--fail-on-severity CRITICAL,HIGH` | Exits `1` if any finding at `CRITICAL` or `HIGH` severity is present, failing the job |
| `--output-dir /reports` | Writes all output files into the mounted directory |

See [CLI reference](../cli-reference.md) for the full list of flags, including `--severity`, `--offline`, `--baseline-image`, and more.

## Container Registry authentication

### GitLab Container Registry (auto-injected)

When your image lives in the same project's GitLab Container Registry, no manual secret setup is needed. GitLab automatically injects `CI_REGISTRY_USER` and `CI_REGISTRY_PASSWORD` as short-lived job tokens scoped to the current pipeline. They expire when the pipeline finishes and are rotated on each run.

```yaml
before_script:
  - echo "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY"
      --username "$CI_REGISTRY_USER" --password-stdin
```

This is the approach used in the example above. It works for both the `build` (push) and `container-scan` (pull) jobs without any additional configuration.

### External registries (Docker Hub, AWS ECR, GCR, Azure ACR)

If your application image or scanner image is stored in an external registry, add the credentials as CI/CD variables (see the next section) and call `docker login` with the appropriate hostname:

```yaml
before_script:
  # Docker Hub
  - echo "$DOCKERHUB_TOKEN" | docker login
      --username "$DOCKERHUB_USERNAME" --password-stdin

  # AWS ECR (requires AWS CLI in the job image)
  - aws ecr get-login-password --region "$AWS_REGION" |
      docker login --username AWS --password-stdin "$ECR_REGISTRY"

  # Google Artifact Registry
  - echo "$GCP_SA_KEY" | docker login europe-docker.pkg.dev
      --username _json_key --password-stdin
```

## Custom secrets: CI/CD Variables

Secrets such as registry passwords, API tokens, and signing keys must never be committed to the repository. Store them as **CI/CD Variables** in GitLab:

1. Open your project in GitLab and go to **Settings → CI/CD**.
2. Expand the **Variables** section.
3. Click **Add variable** and fill in the key and value.
4. Configure the protection flags appropriate for the secret:

| Flag | When to enable |
|---|---|
| **Masked** | Enable for passwords and tokens — the value is redacted from job logs wherever it appears |
| **Protected** | Enable to restrict the variable to pipelines running on protected branches and tags (e.g. `main`, release tags); prevents feature branches from accessing production credentials |
| **Expand variable reference** | Leave disabled for secrets that contain `$` characters to avoid unintended shell expansion |

Variables declared at the **Group** level are inherited by all projects in the group, which is useful for shared registry credentials or organisation-wide scanner configuration.

### Example: adding a Docker Hub token

| Key | Value | Masked | Protected |
|---|---|---|---|
| `DOCKERHUB_USERNAME` | `myorg-bot` | No | No |
| `DOCKERHUB_TOKEN` | `dckr_pat_…` | Yes | Yes |

Access the values in `.gitlab-ci.yml` exactly as shown above — GitLab injects them as environment variables.

## SARIF upload and the Security dashboard

The `reports: container_scanning:` key in the `artifacts` block is what connects the scanner output to GitLab's Security features. When a job declares this artifact, GitLab:

1. **Parses the SARIF file** after the job completes (even if the job failed, because `when: always` is set).
2. **Populates the Security dashboard** at the project level (**Security → Vulnerability Report**) with deduplicated findings across pipelines.
3. **Shows the MR Security widget** on the merge request page, listing new findings introduced by the branch and any findings resolved by it.

```yaml
artifacts:
  when: always          # upload even when --fail-on-severity causes a non-zero exit
  reports:
    container_scanning: reports/report.sarif
  paths:
    - reports/          # also available as downloadable artifacts
```

The `paths` entry makes the full set of report files (`report.md`, `report.html`, `report.csv`, SBOM) downloadable from the **Job artifacts** section of the pipeline UI, in addition to the parsed Security dashboard view.

> **GitLab tier note.** The Security dashboard and MR Security widget require GitLab Ultimate. On Free and Premium tiers the SARIF file is still uploaded as a downloadable artifact and can be viewed locally or imported into other tools; only the integrated dashboard view is gated.

## `--fail-on-severity` gate and job failure behaviour

Passing `--fail-on-severity CRITICAL,HIGH` causes the scanner to exit with code `1` when any finding at those severity levels is present. GitLab treats a non-zero exit from any script line as a job failure, which:

- **Marks the pipeline as failed**, blocking merge if branch protection rules require a passing pipeline.
- **Does not suppress artifact upload** when `artifacts: when: always` is set — reports are still published to the Security dashboard and available for download.

To adjust the policy without changing the pipeline file, modify the severity list:

```yaml
# Block only on critical findings
--fail-on-severity CRITICAL

# Block on medium and above
--fail-on-severity CRITICAL,HIGH,MEDIUM

# Scan without blocking (report only)
# Omit --fail-on-severity entirely
```

You can also externalise the severity list as a CI/CD variable so it can be updated without a code change:

```yaml
variables:
  FAIL_ON_SEVERITY: "CRITICAL,HIGH"

# In the scan script:
--fail-on-severity "$FAIL_ON_SEVERITY"
```

## Scheduled re-scans

New CVEs are published continuously. To catch vulnerabilities in already-deployed images without waiting for a code push, create a **Scheduled pipeline** in GitLab:

1. Go to **CI/CD → Schedules** in your project.
2. Click **New schedule**, set the interval (e.g. `0 3 * * *` for 03:00 UTC daily), and target the `main` branch.
3. The pipeline runs the full `build` + `container-scan` sequence on the latest `main` commit.

The `container-scan` job can also be written to pull an already-pushed image by SHA or by a stable tag, skipping the build stage entirely for re-scan runs.

## Example file

See [ci/gitlab/job.example.yml](../../ci/gitlab/job.example.yml) for the full, copy-paste-ready job definition.

Replace `${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}` with your image reference if you are not using the GitLab Container Registry.
