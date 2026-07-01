# Jenkins Pipelines integration

Add the Docker Container Scanner to your Jenkins declarative pipeline so every build is scanned, policy gates are enforced, and reports are archived as build artifacts — even when the scan fails.

## Prerequisites

- **Jenkins 2.387+** with the [Pipeline](https://plugins.jenkins.io/workflow-aggregator/) plugin suite installed.
- **Docker available on the agent** — either installed directly on the build node or exposed via a Docker agent label. See [Docker socket vs Docker-in-Docker](#docker-socket-mount-vs-docker-agent) below.
- **Scanner image reachable** from the build node: either the pre-published image (`ghcr.io/beejak/docker-scanner:latest`) or a locally built image from this repository.
- **Warnings Next Generation plugin** (optional) — enables SARIF results to appear as annotations on the build page. Install via **Manage Jenkins → Plugins → Available plugins → "Warnings Next Generation"**.

## Built-in Jenkins environment variables

Jenkins injects the following variables into every build. The example pipeline uses several of them to produce stable, traceable image tags and report paths.

| Variable | Example value | Typical use |
|----------|--------------|-------------|
| `BUILD_NUMBER` | `42` | Append to image tag so each build produces a distinct image |
| `GIT_COMMIT` | `a3f1d9c...` | Full SHA of the checked-out commit; use for precise traceability |
| `WORKSPACE` | `/var/jenkins/workspace/my-app` | Absolute path to the job workspace on the agent; mount subdirectories into Docker containers |
| `JOB_NAME` | `my-org/my-app/main` | Folder-qualified job name; useful for labelling reports or registry paths |
| `BUILD_TAG` | `jenkins-my-app-42` | Unique slug combining job name and build number; safe to use as a Docker tag |

## Docker socket mount vs Docker agent

Jenkins pipelines have two common ways to run Docker commands inside a build.

### Docker socket mount (recommended)

The agent node runs a Docker daemon and Jenkins mounts `/var/run/docker.sock` into the build container. Any `docker` commands issued in pipeline steps talk to that daemon and can see images built earlier in the same job.

```groovy
agent any   // or agent { label 'docker' }
```

Inside `sh` steps, mount the socket explicitly when running the scanner:

```sh
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ${REPORTS_DIR}:/reports \
  ${SCANNER_IMAGE} scan --image ${IMAGE_NAME} ...
```

This is the approach used in the example pipeline below. The application image built in the `Build` stage is immediately visible to the scanner in the `Scan` stage because both share the same daemon.

### Docker agent (`agent { docker { ... } }`)

Jenkins can run each stage inside a Docker container using `agent { docker { image '...' } }`. This is clean for build environments but introduces a problem for scanning: the scanner needs access to the Docker daemon and the images built in previous stages. When each stage runs in a fresh container, images built earlier are not automatically present unless you:

- Save the image to a tar file and load it in the scan stage, or
- Push the image to a registry between stages and pull it in the scan stage.

### Docker-in-Docker (DinD) — avoid for scanning

DinD runs a separate Docker daemon inside the build container. Images built inside DinD are invisible to the host daemon and vice versa. The scanner cannot reach those images via the socket mount, leading to "image not found" errors. Use the socket mount approach instead.

## Full annotated Jenkinsfile

The pipeline below has three stages (Build, Scan, post) and covers every topic in this guide. Copy it to your repository as `Jenkinsfile` and adjust the environment variables at the top.

```groovy
// Jenkinsfile — Docker Container Scanner integration
//
// Prerequisites:
//   - Docker available on the Jenkins agent
//   - Scanner image accessible (build locally or pull from registry)
//   - Warnings Next Generation plugin (optional, for recordIssues)
//
// Customise IMAGE_NAME, SCANNER_IMAGE, and --fail-on-severity to suit your project.

pipeline {
  // Run on any agent that has Docker. Narrow this with a label if needed:
  //   agent { label 'docker' }
  agent any

  environment {
    // Tag the application image with the build number so each run is distinct.
    // Swap BUILD_NUMBER for GIT_COMMIT for SHA-based tags.
    IMAGE_NAME    = "app:${env.BUILD_NUMBER}"

    // Use the pre-published scanner image or build your own:
    //   sh 'docker build -t scanner:latest .'
    SCANNER_IMAGE = 'ghcr.io/beejak/docker-scanner:latest'

    // All report files land under WORKSPACE/reports so archiveArtifacts
    // can pick them up with a simple glob.
    REPORTS_DIR   = "${env.WORKSPACE}/reports"
  }

  triggers {
    // Nightly re-scan at 02:00 ensures new CVEs added to the Trivy database
    // overnight are caught even when no code changes were pushed.
    cron('0 2 * * *')
  }

  stages {

    // ------------------------------------------------------------------ //
    // Stage 1 — Build                                                     //
    // ------------------------------------------------------------------ //
    stage('Build') {
      steps {
        // Build the application image. The tag includes BUILD_NUMBER so the
        // scanner can refer to it unambiguously in the next stage.
        sh 'docker build -t ${IMAGE_NAME} .'
      }
    }

    // ------------------------------------------------------------------ //
    // Stage 2 — Scan                                                      //
    // ------------------------------------------------------------------ //
    stage('Scan') {
      steps {
        // Create the reports directory on the host. This path is bind-mounted
        // into the scanner container at /reports.
        sh 'mkdir -p ${REPORTS_DIR}'

        // Run the scanner. Key flags explained inline below.
        sh '''
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v ${REPORTS_DIR}:/reports \
            ${SCANNER_IMAGE} scan \
              --image ${IMAGE_NAME} \
              --output-dir /reports \
              --format sarif,markdown,html,csv \
              --check-runtime \
              --sbom \
              --fail-on-severity CRITICAL,HIGH
        '''
        // Flag reference:
        //
        //  --image              Image to scan; must be visible to the Docker daemon
        //                       reached via the socket mount above.
        //
        //  --output-dir         Directory inside the container where reports are
        //                       written. Bind-mounted to REPORTS_DIR on the host.
        //
        //  --format             Comma-separated list of output formats.
        //                       sarif     → reports/report.sarif  (SAST tooling)
        //                       markdown  → reports/report.md     (PR comments)
        //                       html      → reports/report.html   (human review)
        //                       csv       → reports/report.csv    (spreadsheet)
        //
        //  --check-runtime      Also checks the agent's runc binary for container-
        //                       escape CVEs (e.g. CVE-2024-21626).
        //
        //  --sbom               Writes a CycloneDX SBOM to reports/report.cdx.json.
        //
        //  --fail-on-severity   Exit code 1 when any finding at or above the given
        //                       severity is present. CRITICAL,HIGH is a reasonable
        //                       default; adjust to CRITICAL for less strict gating.
        //                       Exit code 1 causes Jenkins to mark the stage FAILED.
      }
    }

  }

  // -------------------------------------------------------------------- //
  // post — runs after all stages, regardless of outcome                  //
  // -------------------------------------------------------------------- //
  post {
    always {
      // Archive every file under reports/ as a build artifact.
      //
      // Using post { always {} } is essential: if the scan exits 1 (policy
      // violation), the Scan stage is marked FAILED and no further stages run,
      // but post { always } still executes. Without it, reports from a failed
      // scan would be lost.
      //
      // allowEmptyArchive: true prevents a secondary error when no reports
      // were produced (e.g. the scanner crashed before writing files).
      archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true

      // Publish a short Markdown summary in the build description so
      // reviewers can read the top findings without downloading a file.
      script {
        def mdReport = "${env.REPORTS_DIR}/report.md"
        if (fileExists(mdReport)) {
          def summary = readFile(mdReport).take(2000)
          currentBuild.description = "<pre>${summary}</pre>"
        }
      }

      // Optional: publish SARIF results via the Warnings Next Generation plugin.
      // When the plugin is installed, this adds an "Issues" tab to the build
      // page with filterable, linkable findings — no manual download required.
      // Remove or comment out the line below if the plugin is not installed.
      recordIssues(tools: [sarif(pattern: 'reports/report.sarif')])
    }

    failure {
      echo 'Scan failed or policy gate triggered. Download reports/ artifacts for details.'
    }
  }
}
```

See [ci/jenkins/Jenkinsfile.example](../../ci/jenkins/Jenkinsfile.example) for the copy-paste-ready version of this file.

## Archiving artifacts after a failed scan

When `--fail-on-severity` finds a matching vulnerability the scanner exits with code `1`, which marks the `Scan` stage as **FAILED**. Jenkins does not execute further stages after a failure, but `post { always {} }` runs unconditionally — this is the correct place for `archiveArtifacts`.

```groovy
post {
  always {
    archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
  }
}
```

To view archived reports:

1. Open the failed build in the Jenkins UI.
2. Click **Build Artifacts** in the left-hand sidebar (or the **Artifacts** link on the build summary page).
3. Download or open `report.sarif`, `report.md`, `report.html`, or `report.csv`.

## SARIF viewer: Warnings Next Generation plugin

### With the plugin installed

The `recordIssues` step (already included in the example pipeline) ingests the SARIF file and renders findings directly in the Jenkins build UI:

```groovy
recordIssues(tools: [sarif(pattern: 'reports/report.sarif')])
```

After the build:

1. Open the build page.
2. Click the **Issues** tab (added by the plugin).
3. Browse, filter, and sort findings by severity, file, or rule ID.
4. Trend charts across builds are available on the job page.

### Without the plugin

The SARIF file is still archived as a build artifact and can be:

- Downloaded and opened in **VS Code** with the [SARIF Viewer extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer).
- Uploaded to **GitHub Code Scanning** via the `github/codeql-action/upload-sarif` action for annotation on pull requests.
- Opened directly in any other SARIF-compatible tool.

## Credentials: private registry authentication

If your application image or the scanner image is in a private registry, store credentials in Jenkins and inject them at runtime. Never hard-code passwords or tokens in the `Jenkinsfile`.

### Adding credentials in Jenkins

1. Go to **Manage Jenkins → Credentials → System → Global credentials (unrestricted)**.
2. Click **Add Credentials**.
3. For a registry username and password, choose **Username with password**; for a token or API key, choose **Secret text**.
4. Set a memorable **ID** (e.g. `docker-registry-creds` or `scanner-registry-token`).

### Using `withCredentials` in the pipeline

**Username and password** (e.g. Docker Hub, self-hosted registry):

```groovy
stage('Scan') {
  steps {
    withCredentials([usernamePassword(
      credentialsId: 'docker-registry-creds',
      usernameVariable: 'REGISTRY_USER',
      passwordVariable: 'REGISTRY_PASS'
    )]) {
      sh '''
        echo "$REGISTRY_PASS" | docker login \
          --username "$REGISTRY_USER" \
          --password-stdin

        docker pull ${SCANNER_IMAGE}

        docker run --rm \
          -v /var/run/docker.sock:/var/run/docker.sock \
          -v ${REPORTS_DIR}:/reports \
          ${SCANNER_IMAGE} scan \
            --image ${IMAGE_NAME} \
            --output-dir /reports \
            --format sarif,markdown,html \
            --fail-on-severity CRITICAL,HIGH
      '''
    }
  }
}
```

**Secret text** (e.g. a registry token or API key):

```groovy
withCredentials([string(credentialsId: 'scanner-registry-token', variable: 'REGISTRY_TOKEN')]) {
  sh '''
    echo "$REGISTRY_TOKEN" | docker login ghcr.io \
      --username _token \
      --password-stdin
  '''
}
```

For registries that require a hostname (AWS ECR, GCR, Azure ACR), add the hostname to the `docker login` command and store it as an additional secret or a plain environment variable:

```groovy
environment {
  REGISTRY_HOST = 'your-account.dkr.ecr.us-east-1.amazonaws.com'
}
```

```sh
docker login "$REGISTRY_HOST" \
  --username "$REGISTRY_USER" \
  --password-stdin <<< "$REGISTRY_PASS"
```

Jenkins masks the values of variables bound by `withCredentials` in the build log, so credentials never appear in plain text.

## `--fail-on-severity` policy gate

The `--fail-on-severity` flag causes the scanner to exit with code `1` when at least one finding at or above the specified severity is present. Jenkins interprets a non-zero exit code from an `sh` step as a stage failure.

```sh
--fail-on-severity CRITICAL,HIGH
```

| Exit code | Meaning | Jenkins build result |
|-----------|---------|---------------------|
| `0` | No findings above the threshold | Stage passes |
| `1` | One or more findings at or above threshold | Stage marked **FAILED** |

Adjust the threshold to match your team's risk tolerance:

| Value | Effect |
|-------|--------|
| `CRITICAL` | Only block on the most severe findings |
| `CRITICAL,HIGH` | Block on critical and high (recommended starting point) |
| `CRITICAL,HIGH,MEDIUM` | Stricter; suitable for regulated environments |

To make the pipeline continue (collect reports) rather than fail hard when the gate triggers, wrap the `sh` step with `catchError`:

```groovy
catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
  sh '''
    docker run --rm ... --fail-on-severity CRITICAL,HIGH
  '''
}
```

This marks the build **UNSTABLE** instead of **FAILED**, which can be useful when introducing the scanner to an existing project with a large backlog of findings.

## Nightly cron trigger

New CVEs are published continuously. A scheduled nightly scan catches vulnerabilities that appear in the Trivy database between code pushes:

```groovy
triggers {
  cron('0 2 * * *')
}
```

This follows standard cron syntax (`minute hour day month weekday`). The example runs at 02:00 every night. To additionally trigger on every push, combine with an SCM poll or use a webhook:

```groovy
triggers {
  cron('0 2 * * *')   // nightly
  pollSCM('H/5 * * * *')  // poll SCM every 5 minutes (use webhooks instead when possible)
}
```

## CLI reference

See [CLI reference](../cli-reference.md) for the full list of scanner flags, including `--severity`, `--offline`, `--baseline-image`, `--sbom`, `--check-runtime`, and output format options.
