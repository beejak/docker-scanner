# Getting started

## Prerequisites

- Docker (to run the scanner image or to scan images)
- Optional: Go 1.21+ (to build from source)

## Install

### Option A: Docker image (recommended for CI)

```bash
docker pull <your-registry>/scanner:latest
```

### Option B: Build from source

```bash
git clone <repo>
cd docker-scanner
go build -o scanner ./cmd/cli
```

## First scan

1. Ensure Docker is running and you can pull images (or use a local image).
2. Run the scanner:

   ```bash
   # Using the built binary
   ./scanner scan --image alpine:latest --output-dir ./reports

   # Or using Docker
   docker run --rm -v $PWD/reports:/reports scanner:latest scan --image alpine:latest --output-dir /reports
   ```

3. Open `./reports/report.md` (or `report.sarif` / `report.html`) to view findings and remediation. Reports include **Exploitable** (CISA KEV), **Why severity**, and **Exploit info**; see [Vulnerability reports](vulnerability-reports.md).

**Windows without PATH:** If Go and Trivy are not on your Path, run `scripts\run-scan-local.bat` from the repo root. It uses Trivy and Go from `Downloads\trivy_*` and `Program Files\Go\bin`; reports appear in `reports\`.

## Next steps

- [CLI reference](cli-reference.md) — All commands and flags.
- [CI integration](ci/README.md) — Add the scanner to Azure, GitHub, GitLab, or Jenkins.
- [Troubleshooting](troubleshooting.md) — Common errors and fixes.
