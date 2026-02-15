# Jenkins integration

Add the Docker Container Scanner to your pipeline so every build is scanned and reports are archived.

## Prerequisites

- Jenkins has Docker available (agent or Docker pipeline).
- Scanner image is available: build from this repo or pull from your registry.

## Steps

1. **Build your app image** in a stage.
2. **Run the scanner** in a stage; mount a workspace directory for reports (e.g. `reports/`).
3. **Archive artifacts** in `post { always { archiveArtifacts ... } }` so SARIF and Markdown are available.
4. **Optional:** Use a plugin (e.g. Warnings NG with SARIF format) to publish issues to the build.

## Example

See [ci/jenkins/Jenkinsfile.example](../../ci/jenkins/Jenkinsfile.example) for a full pipeline example.

Replace `IMAGE_NAME` with your built image (e.g. `app:${BUILD_NUMBER}`).

## Registry auth

Add Docker credentials in Jenkins (e.g. "Docker Registry" credentials) and use `docker login` in a step if your image or the scanner image is in a private registry.

## CLI reference

See [CLI reference](../cli-reference.md) for all flags (`--severity`, `--offline`, `--baseline-image`, etc.).
