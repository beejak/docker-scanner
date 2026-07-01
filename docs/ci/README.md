# CI integration

Add the scanner to your pipeline so every build is scanned and reports (SARIF + Markdown/HTML) are published.

## Cloud-hosted CI

- [GitHub Actions](github-actions.md) — Workflow step, upload-sarif, artifacts
- [GitLab CI](gitlab-ci.md) — Job, Security dashboard, artifacts
- [CircleCI](circleci.md) — Two-job workflow, workspace file passing, artifacts
- [Bitbucket Pipelines](bitbucket-pipelines.md) — Docker service, custom pipeline, artifacts
- [Azure DevOps](azure-devops.md) — YAML task, PublishSecurityAnalysisResults, artifacts

## Cloud-provider CI / build systems

- [AWS CodeBuild](aws-codebuild.md) — buildspec.yml, ECR push/pull, S3 artifacts, Security Hub SARIF import
- [Google Cloud Build](google-cloud-build.md) — cloudbuild.yaml, Artifact Registry, GCS artifact upload

## Self-hosted / Kubernetes-native

- [Jenkins](jenkins.md) — Pipeline stage, SARIF plugin, artifacts
- [Tekton](tekton.md) — Task + Pipeline CRDs, PVC workspace, Kaniko build step

---

Each guide covers: how to pass the image ref from the build step, how to run the scanner (Docker image or CLI binary), how to gate the build on severity, how to publish SARIF and Markdown/HTML reports, and how to set registry credentials.

See also [CLI reference](../cli-reference.md) for all flags and options.
