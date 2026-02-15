# GitHub Actions integration

Add the Docker Container Scanner to your workflow so every push/PR is scanned and SARIF is uploaded to the Security tab.

## Prerequisites

- Workflow runs on a runner with Docker (e.g. `ubuntu-latest`).
- Scanner image is available: build from this repo or use a published image.

## Steps

1. **Build your app image** (or use an existing image ref).
2. **Run the scanner** using the scanner Docker image, passing your image ref and output directory.
3. **Upload SARIF** with `github/codeql-action/upload-sarif` so results appear in the Security tab.
4. **Upload report artifact** (optional) so Markdown/HTML are available as workflow artifacts.

## Example

See [ci/github/workflow.example.yml](../../ci/github/workflow.example.yml) for a full workflow example.

Replace `<IMAGE_NAME>` with your built image (e.g. `app:latest` or `ghcr.io/${{ github.repository }}:latest`).

## Secrets

If your image or the scanner image is in a private registry, add secrets (e.g. `REGISTRY_USERNAME`, `REGISTRY_PASSWORD`) and log in before running the scanner.

## CLI reference

See [CLI reference](../cli-reference.md) for all flags (`--severity`, `--offline`, `--baseline-image`, etc.).
