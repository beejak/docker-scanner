# CI integration

Add the scanner to your pipeline so every build is scanned and reports (SARIF + Markdown/HTML) are published.

- [Azure DevOps](azure-devops.md) — YAML task, PublishSecurityAnalysisResults, artifacts
- [GitHub Actions](github-actions.md) — Workflow step, upload-sarif, artifacts
- [GitLab CI](gitlab-ci.md) — Job, Security dashboard, artifacts
- [Jenkins](jenkins.md) — Pipeline stage, SARIF plugin, artifacts

Each guide: how to get the image name from the build, how to run the scanner (Docker image or CLI), how to publish SARIF and optional Markdown/HTML, and how to set registry/baseline auth.

See also [CLI reference](../cli-reference.md) for all flags and options.
