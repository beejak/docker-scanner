# Azure DevOps integration

Add the Docker Container Scanner to your pipeline so every build is scanned and SARIF is published to the Security tab.

## Prerequisites

- Pipeline has Docker available (e.g. `ubuntu-latest` with Docker).
- Scanner image is available: build from this repo or pull from your registry.

## Steps

1. **Build your app image** (or use an existing image ref).
2. **Run the scanner** using the scanner Docker image, passing your image ref and output directory.
3. **Publish SARIF** with `PublishSecurityAnalysisResults@1` so results appear in the Security tab.
4. **Publish report artifacts** (optional) so Markdown/HTML are available as pipeline artifacts.

## Example

See [ci/azure/pipeline.example.yml](../../ci/azure/pipeline.example.yml) for a full YAML example.

Replace `<IMAGE_NAME>` with your built image (e.g. `$(containerRegistry)/$(imageRepository):$(tag)` or `app:$(Build.BuildId)`).

## Registry auth

If your image or the scanner image is in a private registry, add a Docker service connection and use it in the step that runs the scanner (e.g. login before `docker run`).

## CLI reference

See [CLI reference](../cli-reference.md) for all flags (`--severity`, `--offline`, `--baseline-image`, etc.).
