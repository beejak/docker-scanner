<div align="center">

# Docker Container Scanner

**Production-grade container vulnerability scanner with enriched remediation, CI/CD integration, and runtime advisory.**

[![Go 1.21+](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Powered by Trivy](https://img.shields.io/badge/Powered%20by-Trivy-1904DA?style=flat-square)](https://github.com/aquasecurity/trivy)
[![CISA KEV](https://img.shields.io/badge/Enriched%20with-CISA%20KEV-red?style=flat-square)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![OSV.dev](https://img.shields.io/badge/Enriched%20with-OSV.dev-blue?style=flat-square)](https://osv.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

Scan Docker/Podman images and LXC rootfs for CVEs · Enrich with CISA KEV, OSV.dev, and runc advisories · Output SARIF, Markdown, HTML, CSV, and CycloneDX SBOM · Gate CI/CD pipelines on severity

[Quick Start](#-quick-start) · [Commands](#-command-reference) · [Docker](#-running-with-docker) · [CI/CD](#-cicd-integration) · [Configuration](#-configuration) · [Reports](#-reports--enrichment) · [Docs](docs/)

</div>

---

## What it does

```
docker build -t myapp:latest .
scanner scan --image myapp:latest --output-dir ./reports --format sarif,markdown,html --fail-on-severity CRITICAL,HIGH
```

- Scans **container images** (Docker, Podman, containerd) and **root filesystems** (LXC)
- Finds CVEs via **Trivy** with `--detection-priority comprehensive` (GitHub Advisory DB fallback)
- **Enriches every finding** with CISA KEV exploit status, OSV.dev CVE back-fill, and plain-English remediation
- Detects **host runc container escape CVEs** that image scanners can never see (`--check-runtime`)
- Outputs **SARIF** (Azure/GitHub Security tab), **Markdown**, **HTML**, **CSV**, and **CycloneDX SBOM**
- Exits non-zero on policy violation so pipelines **fail fast** on Critical/High findings

---

## ⚡ Quick Start

### Option A — Docker (no Go or Trivy install needed)

```bash
# Build the scanner image once
docker build -t scanner:latest .

# Scan any image
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/reports:/reports" \
  scanner:latest scan --image alpine:latest \
  --output-dir /reports \
  --format sarif,markdown,html
```

Reports land in `./reports/`. Open `report.html` in a browser or `report.md` in any Markdown viewer.

### Option B — From source (Go 1.21+ and Trivy required)

```bash
# Install Go + Trivy in one step (runs in background)
./scripts/install-deps.sh          # Linux/macOS
.\scripts\install-deps.ps1         # Windows PowerShell

# Build
go build -o scanner ./cmd/cli

# Scan
./scanner scan --image alpine:latest --output-dir ./reports
```

### Option C — Windows without PATH

```bat
scripts\run-scan-local.bat alpine:latest
```

Uses Trivy and Go from known default install paths. Reports go to `reports\`.

> **Tip — avoid overwriting old reports:** add `--timestamp` to write unique filenames per run, e.g. `report-20060102-150405.html`.

---

## 📖 Command Reference

### `scan`

```
scanner scan --image <ref> [flags]
scanner scan --fs    <path> [flags]   # rootfs (e.g. LXC)
scanner scan --lxc   <name> [flags]   # Linux: /var/lib/lxc/<name>/rootfs
```

Use `--image` **or** `--fs`/`--lxc`, never both. `--dockerfile` is only valid with `--image`.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--image` | — | Image to scan. e.g. `alpine:latest`, `myregistry.io/app:v1` |
| `--fs` | — | Path to root filesystem (e.g. LXC rootfs) |
| `--lxc` | — | LXC container name → `/var/lib/lxc/<name>/rootfs` (Linux only) |
| `--dockerfile` | — | Dockerfile path; scans it for misconfigurations alongside the image |
| `--severity` | `CRITICAL,HIGH,`<br>`MEDIUM,LOW,UNKNOWN` | Comma-separated severities to include |
| `--format` | `sarif,markdown` | Output formats: `sarif`, `markdown`, `html`, `csv` |
| `--output-dir` | `./reports` | Directory to write reports to |
| `--output-name` | `report` | Base filename (e.g. `myapp` → `myapp.md`, `myapp.sarif`) |
| `--timestamp` | `false` | Append timestamp to base name so runs don't overwrite each other |
| `--fail-on-severity` | — | Exit 1 if any finding matches (e.g. `CRITICAL,HIGH`) |
| `--fail-on-count` | — | Exit 1 if count ≥ N for a severity (e.g. `HIGH:5`) |
| `--check-runtime` | `false` | Check host runc version for known container escape CVEs |
| `--sbom` | `false` | Generate CycloneDX SBOM — `<name>.cdx.json` (image scans only) |
| `--offline` | `false` | Skip DB update, CISA KEV, and OSV.dev; use local cache only |
| `--cache-dir` | system default | Trivy DB cache directory |
| `--config` | auto-detected | Path to `scanner.yaml`; auto-detects in current directory |

#### Examples

```bash
# Minimal scan — SARIF + Markdown to ./reports
scanner scan --image nginx:1.25

# Full output, fail on Critical/High, with SBOM
scanner scan --image myapp:v2 \
  --format sarif,markdown,html,csv \
  --sbom \
  --fail-on-severity CRITICAL,HIGH \
  --output-dir ./reports

# Scan image and its Dockerfile together
scanner scan --image myapp:latest --dockerfile ./Dockerfile

# Scan LXC container rootfs (Linux)
scanner scan --lxc my-container

# Check host runc for container escape CVEs
scanner scan --image myapp:latest --check-runtime

# Offline scan (air-gapped environment)
scanner scan --image myapp:latest --offline --cache-dir /mnt/trivy-cache

# Unique report per run
scanner scan --image alpine:latest --timestamp
```

#### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no policy violation |
| `1` | Policy violated (`--fail-on-severity` or `--fail-on-count` triggered) or scan error |

---

### `db update`

```bash
scanner db update [--cache-dir <dir>]
```

Refreshes the Trivy vulnerability database. Schedule this once a day for fresher results:

```bash
# Linux/macOS — cron (3 AM daily)
0 3 * * * /path/to/scripts/update-trivy-db.sh

# Windows — Task Scheduler
powershell -File "C:\path\to\scripts\update-trivy-db.ps1"
```

---

## 🐳 Running with Docker

### Build once, scan anything

```bash
docker build -t scanner:latest .
```

### Scan a local image

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/reports:/reports" \
  scanner:latest scan \
    --image myapp:latest \
    --format sarif,markdown,html \
    --output-dir /reports
```

### Fail on Critical or High (for use in pipelines)

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/reports:/reports" \
  scanner:latest scan \
    --image myapp:latest \
    --format sarif,markdown,html,csv \
    --fail-on-severity CRITICAL,HIGH \
    --output-dir /reports
```

### Generate SBOM alongside the report

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/reports:/reports" \
  scanner:latest scan \
    --image myapp:latest \
    --sbom \
    --output-dir /reports
# Produces reports/report.cdx.json (CycloneDX)
```

### Scan with a persistent cache (faster repeated scans)

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/reports:/reports" \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  scanner:latest scan \
    --image myapp:latest \
    --output-dir /reports
```

### Air-gapped / offline

```bash
# Pre-populate cache on a connected host
docker run --rm \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  scanner:latest db update

# Copy the cache to the air-gapped host, then:
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/reports:/reports" \
  -v "/mnt/trivy-cache:/cache" \
  scanner:latest scan \
    --image myapp:latest \
    --offline \
    --cache-dir /cache \
    --output-dir /reports
```

> **Windows (cmd.exe):** Replace `$PWD` with `%CD%` and `$HOME` with `%USERPROFILE%`.

---

## 🔁 CI/CD Integration

The scanner is a single binary (or container). Drop it into any pipeline after your build step.

### Pipeline pattern

```
Build image → docker login (secret) → Run scanner → Publish reports → [Fail on severity]
```

### GitHub Actions

```yaml
name: Container Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: Build app image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Build scanner
        run: docker build -t scanner:latest .

      - name: Run security scan
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v ${{ github.workspace }}/reports:/reports \
            scanner:latest scan \
              --image myapp:${{ github.sha }} \
              --format sarif,markdown,html,csv \
              --sbom \
              --check-runtime \
              --fail-on-severity CRITICAL,HIGH \
              --output-dir /reports

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/report.sarif

      - name: Upload reports as artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scan-reports-${{ github.sha }}
          path: reports/
```

> Full template: `ci/github/workflow.example.yml`

### Azure DevOps

```yaml
trigger:
  branches:
    include: [main, develop]

pool:
  vmImage: ubuntu-latest

steps:
  - task: Docker@2
    displayName: Build app image
    inputs:
      command: build
      tags: myapp:$(Build.BuildId)

  - script: docker build -t scanner:latest .
    displayName: Build scanner

  - script: |
      mkdir -p $(Build.ArtifactStagingDirectory)/reports
      docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v $(Build.ArtifactStagingDirectory)/reports:/reports \
        scanner:latest scan \
          --image myapp:$(Build.BuildId) \
          --format sarif,markdown,html,csv \
          --sbom \
          --fail-on-severity CRITICAL,HIGH \
          --output-dir /reports
    displayName: Run security scan

  - task: PublishSecurityAnalysisResults@1
    displayName: Publish SARIF to Security tab
    inputs:
      ArtifactName: CodeAnalysisLogs
      ArtifactType: Container
    condition: always()

  - task: PublishPipelineArtifact@1
    displayName: Publish scan reports
    inputs:
      targetPath: $(Build.ArtifactStagingDirectory)/reports
      artifact: scan-reports
    condition: always()
```

> Full template: `ci/azure/pipeline.example.yml`

### GitLab CI

```yaml
container-scan:
  stage: test
  image: docker:24
  services:
    - docker:24-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    - docker build -t scanner:latest .
    - mkdir -p reports
    - docker run --rm
        -v /var/run/docker.sock:/var/run/docker.sock
        -v "$CI_PROJECT_DIR/reports:/reports"
        scanner:latest scan
          --image myapp:$CI_COMMIT_SHA
          --format sarif,markdown,html,csv
          --sbom
          --fail-on-severity CRITICAL,HIGH
          --output-dir /reports
  artifacts:
    when: always
    paths:
      - reports/
    reports:
      sast: reports/report.sarif
```

> Full template: `ci/gitlab/pipeline.example.yml`

### Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'docker build -t myapp:${BUILD_NUMBER} .'
        sh 'docker build -t scanner:latest .'
      }
    }
    stage('Scan') {
      steps {
        sh '''
          mkdir -p reports
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v ${WORKSPACE}/reports:/reports \
            scanner:latest scan \
              --image myapp:${BUILD_NUMBER} \
              --format sarif,markdown,html,csv \
              --sbom \
              --fail-on-severity CRITICAL,HIGH \
              --output-dir /reports
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
    }
  }
}
```

> Full template: `ci/jenkins/Jenkinsfile.example`

### CI Quick-reference

| Goal | Flag |
|------|------|
| Fail on Critical/High findings | `--fail-on-severity CRITICAL,HIGH` |
| Fail when ≥ 5 High findings | `--fail-on-count HIGH:5` |
| Generate CycloneDX SBOM | `--sbom` |
| Check host runc escape CVEs | `--check-runtime` |
| Skip DB update (offline runner) | `--offline --cache-dir /cache` |
| Unique artifact per run | `--timestamp` |
| All formats | `--format sarif,markdown,html,csv` |

> **Secrets:** Never put registry passwords in YAML. Use `docker login` with your pipeline's secret store (GitHub Secrets, Azure Key Vault, GitLab CI/CD Variables, Jenkins Credentials).

---

## ⚙️ Configuration

### Config file (`scanner.yaml`)

Drop a `scanner.yaml` (or `.scanner.yaml`) in your project root to set defaults. CLI flags always override config values.

```yaml
# scanner.yaml
severity: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
format: sarif,markdown,html
output-dir: ./reports
output-name: report
# cache-dir: /mnt/trivy-cache   # optional

# Pipeline gate — uncomment to enable:
# fail-on-severity: CRITICAL,HIGH
# fail-on-count: HIGH:5
```

Supported keys: `severity`, `format`, `output-dir`, `output-name`, `cache-dir`, `fail-on-severity`, `fail-on-count`.

Copy the example: `cp scanner.yaml.example scanner.yaml`

### Registry authentication

```bash
# Docker Hub
docker login

# Private registry
docker login myregistry.io

# GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# AWS ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789.dkr.ecr.us-east-1.amazonaws.com
```

The scanner reads from Docker's credential store automatically. Never pass credentials via flags.

---

## 📊 Reports & Enrichment

### Report formats

| Format | File | Use for |
|--------|------|---------|
| `sarif` | `report.sarif` | GitHub / Azure Security tab, Code Scanning |
| `markdown` | `report.md` | PR comments, human review |
| `html` | `report.html` | Browser view; browser Print→PDF for compliance |
| `csv` | `report.csv` | Spreadsheets, custom dashboards |
| SBOM (`--sbom`) | `report.cdx.json` | Dependency-Track, GitHub Dependency Graph, DORA |

Use `--format sarif,markdown,html,csv` to generate all at once.

### What every report includes

Beyond CVE, Package, and Severity, every report contains:

| Column | What it means |
|--------|---------------|
| **Exploitable** | `yes` = in CISA Known Exploited Vulnerabilities catalog (prioritize these). `no` = not in KEV. `unknown` = offline or non-CVE. |
| **Why severity** | Plain-English reason: *"Critical: often RCE, auth bypass…"* |
| **Exploit info** | CISA KEV description when available, including ransomware campaign usage |
| **Remediation** | Exact upgrade command: *"Upgrade curl from 7.88.1 to 7.88.2"* |
| **Links** | NVD, Aqua AVD, OSV.dev advisory |

### Enrichment sources

**CISA Known Exploited Vulnerabilities (KEV)**
Any CVE in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is marked `Exploitable = yes` and promoted to CRITICAL severity so you never miss it. The catalog is fetched online and cached for 24 hours.

**OSV.dev**
For findings Trivy returns without a CVE ID, the scanner queries [OSV.dev](https://osv.dev/) to back-fill the identifier and add an advisory link. Covers Go modules, npm, PyPI, Rust, Maven, and more. Results are cached in-process. Skipped with `--offline`.

**GitHub Advisory Database (GHSA)**
In online mode, Trivy runs with `--detection-priority comprehensive`, falling back to GHSA when NVD data is incomplete. Catches Go stdlib and Java stdlib CVEs that the default mode silently misses.

**Host runc advisory (`--check-runtime`)**
runc is the container runtime on the host — not a package inside images — so Trivy cannot detect it. `--check-runtime` reads the host runc version (via `docker version` or `runc --version`) and flags:

| CVE | Severity | Fixed in | Impact |
|-----|----------|----------|--------|
| CVE-2025-31133 | CRITICAL | 1.2.8 | maskedPaths bypass → arbitrary host path write |
| CVE-2025-52565 | CRITICAL | 1.2.8 | `/dev/console` bind-mount escape before LSM activates |
| CVE-2025-52881 | CRITICAL | 1.2.8 | LSM bypass via shared mounts → host crash or full breakout |
| CVE-2024-21626 | HIGH | 1.1.12 | LEAKY VESSELS: working directory escape via leaked fd |

Findings appear as normal rows in all report formats with `Package=runc` and `Path=host-runtime`.

---

## 🗂 Project Layout

```
docker-scanner/
├── cmd/
│   ├── cli/            # Main CLI (scan, db update)
│   ├── baseline/       # Parallel baseline scanner (100+ images)
│   ├── server/         # Optional HTTP server for Web UI
│   └── mcp-server/     # MCP server for AI assistants
├── pkg/
│   ├── scanner/        # Trivy invocation + JSON parsing
│   ├── remediate/      # Enrichment: CISA KEV, OSV.dev, remediation text
│   ├── kev/            # CISA KEV catalog client (24h cache)
│   ├── osv/            # OSV.dev API client (in-process cache)
│   ├── runc/           # Host runc version detection + advisory table
│   ├── report/         # SARIF, Markdown, HTML, CSV generation
│   ├── policy/         # fail-on-severity / fail-on-count evaluation
│   └── config/         # scanner.yaml loader
├── ide/
│   ├── vscode/         # VS Code / Cursor extension
│   └── jetbrains/      # IntelliJ / GoLand plugin
├── ci/                 # Pipeline templates (GitHub, Azure, GitLab, Jenkins)
├── docs/               # Full documentation set
├── tests/
│   ├── integration/    # Integration tests (require Trivy + Docker)
│   └── baseline/       # Image lists for baseline runs
├── web/                # Drag-and-drop web UI (single HTML file, no server)
├── scripts/            # install-deps, update-trivy-db, run-scan, cleanup
├── scanner.yaml.example
└── Dockerfile
```

---

## 🧪 Testing

```bash
# Unit tests — no Trivy or Docker required
go test ./pkg/... -v

# With race detector
go test ./pkg/... -race

# Integration tests — requires Trivy in PATH + Docker for image pull
go test -tags=integration ./tests/integration/... -v

# All-in-one (Windows)
.\scripts\setup-and-test.ps1

# Sanity checklist before a PR (vet + build + unit tests)
# See docs/sanity.md
```

| Package | Tests | Coverage |
|---------|-------|----------|
| `pkg/osv` | 11 — ecosystem mapping, mock HTTP, caching, error cases | `EcosystemFor`, `Query`, cache hit/miss |
| `pkg/runc` | 10 — semver comparison, boundary versions, table integrity | `AdvisoryFindings`, `isVulnerable` |
| `pkg/remediate` | 6 — KEV enrichment, OSV offline skip, runc finding passthrough | `Enrich`, `whySeverityText` |
| `pkg/report` | 5 — SARIF levels, Markdown content, HTML escaping, CSV | All writers |
| `pkg/scanner` | 4 — Trivy JSON parsing, misconfig, file paths | `trivyVulnToFinding` |
| `pkg/policy` | 4 — fail-on-severity, fail-on-count, parse edge cases | `EvaluateFailPolicy`, `ParseFailOnCount` |
| `pkg/config` | 3 — YAML load, missing file, auto-detect | `Load`, `Find` |

---

## 📚 Documentation

| Topic | Link |
|-------|------|
| Plain-language help, glossary, quick start | [docs/HELP.md](docs/HELP.md) |
| Install dependencies, first scan | [docs/getting-started.md](docs/getting-started.md) |
| Every flag and option | [docs/cli-reference.md](docs/cli-reference.md) |
| Adding to CI/CD pipelines | [docs/ci-cd-primer.md](docs/ci-cd-primer.md) |
| Report columns, CISA KEV, OSV, SBOM | [docs/vulnerability-reports.md](docs/vulnerability-reports.md) |
| 100+ image baseline runs | [docs/baseline.md](docs/baseline.md) |
| VS Code, JetBrains, MCP server | [docs/ide-and-mcp.md](docs/ide-and-mcp.md) |
| System architecture and data flow | [docs/system-design.md](docs/system-design.md) |
| Comparison with Trivy, Grype, Snyk, Scout | [docs/COMPARISON.md](docs/COMPARISON.md) |
| Common errors and fixes | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Pre-PR sanity checklist | [docs/sanity.md](docs/sanity.md) |

---

## 🔑 Glossary

| Term | Meaning |
|------|---------|
| **CVE** | A unique ID for a known vulnerability, e.g. `CVE-2024-1234` |
| **Severity** | How serious it is: Critical → High → Medium → Low |
| **Exploitable** | `yes` = actively exploited in the wild (CISA KEV); `no` = not listed; `unknown` = offline |
| **SARIF** | Standard format consumed by GitHub/Azure Security tabs |
| **SBOM** | Software Bill of Materials — full package inventory in CycloneDX JSON |
| **CISA KEV** | US government list of vulnerabilities actively exploited in the wild |
| **OSV.dev** | Google-maintained open vulnerability database covering 20+ ecosystems |
| **runc** | The low-level container runtime underneath Docker/Podman. Not inside images; audited by `--check-runtime` |
| **Offline mode** | `--offline` — use cached DB only, no network calls |
| **Baseline** | Parallel scan of 100+ images; produces timing + findings summary |

---

## License

MIT or Apache-2.0 — aligned with Trivy.
