# Docker Container Scanner

CI/CD-ready, enterprise-grade Docker container scanner: vulnerability reports with remediation guidance, Azure/GitHub/GitLab/Jenkins integration, offline and baseline support (e.g. Docker Hardened Images).

## Quick start

**Option A — Docker (recommended; no Go/Trivy install):**

```bash
docker build -t scanner:latest .
docker run --rm -v %CD%\reports:/reports scanner:latest scan --image alpine:latest --output-dir /reports --format sarif,markdown
# Reports in ./reports/report.sarif and ./reports/report.md
```

**Option B — From source (requires Go 1.21+ and Trivy):**

Install dependencies in one step, then build and run:

| OS | Install deps | Then |
|----|--------------|------|
| **Linux / macOS** | `./scripts/install-deps.sh` (runs in background; use `--foreground` to wait) | `go build -o scanner ./cmd/cli && ./scanner scan --image alpine:latest --output-dir ./reports` |
| **Windows (PowerShell)** | `.\scripts\install-deps.ps1` (runs in background; use `-Foreground` to wait) | `go build -o scanner.exe ./cmd/cli; .\scanner.exe scan --image alpine:latest --output-dir ./reports` |

If Go and Trivy are already in PATH, you can skip the install script and run `go build` and `./scanner scan` directly.

**Option C — Windows without PATH:** Run `scripts\run-scan-local.bat` (uses Trivy/Go from `Downloads\trivy_*` and `Program Files\Go\bin`). Reports in `reports\`. Add `/publish` to open the report in the browser after the scan (e.g. `scripts\run-scan-local.bat alpine:3.10 /publish`).

**Test with many vulnerabilities:** Use the MaxCVE image: `scripts\run-scan-local.bat ghcr.io/chainguard-dev/maxcve/maxcve:latest` (scan takes 1–2 min; see [Troubleshooting](docs/troubleshooting.md)).

**Avoid overwriting reports:** Use `--timestamp` so each run writes unique files (e.g. `report-20060102-150405.html`). Reports can also be CSV (`--format csv`); for PDF, use the browser “Print to PDF” on the HTML report.

**Baseline (100+ images):** Run `go run ./cmd/baseline` from repo root to scan 100+ images in parallel and get a report with findings count and **Duration (s)** per image. Use images from **other registries** (GitHub ghcr.io, Quay.io, Chainguard cgr.dev, Red Hat) to avoid Docker Hub rate limits: set `BASELINE_IMAGES=tests/baseline/images-other-registries.txt`. See [Baseline](docs/baseline.md).

**Drag-and-drop:** Open **`web/index.html`** in your browser. Drop or paste an image reference (e.g. `alpine:3.10`) and the page shows the **CLI** and **Docker** commands with a **Copy** button—no typing needed.

## Features

- **Scan after build**: Run in pipeline right after `docker build`; scan image and optional Dockerfile (`--dockerfile`); SARIF + Markdown/HTML/CSV reports.
- **Remediation**: Per-finding fix guidance (upgrade path, base image, CVE links).
- **CI/CD**: Azure DevOps, GitHub Actions, GitLab CI, Jenkins; same CLI, same reports.
- **Offline**: `--offline` with pre-populated cache; no network for DB or enrichment.
- **Baseline (optional)**: Compare to a reference image (e.g. Docker Hardened Images); report/fail on delta only.
- **Web**: Open `web/index.html` for drag-and-drop: paste or drop an image ref and get CLI + Docker commands with Copy button. Report formats: SARIF, Markdown, HTML, CSV; PDF via browser Print to PDF.
- **Trivy DB**: Run `./scripts/update-trivy-db.sh` (Linux/macOS) or `.\scripts\update-trivy-db.ps1` (Windows) about once a day for fresh vulnerability data; see [Help](docs/HELP.md#updating-the-trivy-database-once-a-day) for scheduling (cron, Task Scheduler).

## Project layout

- `cmd/cli` — CLI entrypoint (`scan`, `db update`, optional `serve`).
- `cmd/server` — Optional HTTP server for Web UI.
- `pkg/scanner` — Invoke Trivy, parse output into internal finding model.
- `pkg/remediate` — Enrich findings with fix text (Trivy + OSV or rules).
- `pkg/report` — SARIF + Markdown/HTML generation.
- `ci/` — Pipeline templates (Azure, GitHub, GitLab, Jenkins).
- `docs/` — System design, getting started, CLI reference, integration guides.
- `web/` — Web UI (drop zone, options, report view).

## Testing

- **Unit tests** (no Trivy required): `go test ./pkg/... -v`
- **Integration tests** (Trivy in PATH; optional Docker for image pull): `go test -tags=integration ./tests/integration/... -v`
- **Install dependencies then test:** Run `./scripts/install-deps.sh` (Linux/macOS) or `.\scripts\install-deps.ps1` (Windows), then run the tests above.
- **Windows — install Go + Trivy and run all tests**: `.\scripts\setup-and-test.ps1` (uses winget or portable installs if needed)
- **Windows without PATH**: `scripts\run-tests.bat` (sets Trivy/Go from known locations, then runs unit + integration tests)

See [Testing](docs/testing.md) for details. Before a PR or release, run the [Sanity checklist](docs/sanity.md) (`go mod tidy`, `go vet`, build, unit tests, optional integration).

## Documentation

- **[Help (plain language)](docs/HELP.md)** — What is this? What do I need installed? What do the words mean? Baseline and cleanup in simple terms. Start here if you’re new.
- [Getting started](docs/getting-started.md) — Install dependencies (one script per OS), first scan, view report.
- [CLI reference](docs/cli-reference.md) — Commands and flags.
- [CI/CD primer](docs/ci-cd-primer.md) — Add the scanner to non‑prod pipelines (layman-friendly). Pipeline templates in `ci/`.
- [Troubleshooting](docs/troubleshooting.md) — Common errors and fixes.
- [Baseline](docs/baseline.md) — 100+ image scan, timing report, baseline for product quality.
- [Image sources](docs/image-sources.md) — Registries, sites, and repos we reference for all image lists; update when adding new sources.
- [Hardened images and local registries](docs/hardened-images-and-local-registries.md) — What hardened images are, your own repo for local use, microservices, and pulling from local/private registries.
- [Vulnerability reports](docs/vulnerability-reports.md) — Exploitable (CISA KEV), why severity, exploit info, and how to use them.
- [Testing](docs/testing.md) — Unit and integration tests.
- [System design](docs/system-design.md) — Architecture, data flow, deployment.
- [Comparison with other scanners](docs/COMPARISON.md) — Where we stand vs Trivy, Grype, Snyk, Docker Scout, and enhancements.
- [Lessons learned](docs/LESSONS-LEARNED.md) — What worked, what didn’t, and what we’d do differently (reviewable log).

## Agents (orchestration)

This repo uses **agents** (Cursor rules + AGENTS.md) to split work by domain. See [AGENTS.md](AGENTS.md) for responsibilities and handoffs.

## Publishing to GitHub

1. **Set Git identity** (once per machine, if not already set):
   ```bash
   git config --global user.name "Your Name"
   git config --global user.email "you@example.com"
   ```
   Use the email associated with your GitHub account.

2. **Create a new repository** on GitHub (e.g. `docker-scanner`). Do not add a README, .gitignore, or license (this repo already has them).

3. **From this folder**, run:
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Docker container scanner with baseline and CI/CD"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/docker-scanner.git
   git push -u origin main
   ```
   Replace `YOUR_USERNAME` with your GitHub username (or use the repo URL GitHub shows).

4. **Optional:** Add a description and topics (e.g. `docker`, `security`, `trivy`, `vulnerability-scanning`) on the repo page.

Baseline outputs (`test-results/`) are in `.gitignore` so they are not pushed; keep reports locally or publish them as pipeline artifacts.

## License

MIT or Apache-2.0 (aligned with Trivy).
