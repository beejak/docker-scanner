# Getting started

This page walks you through **installing** and **running your first scan** in plain steps.

---

## Prerequisites

- **Option A — Docker only:** You need **Docker** installed. You build the scanner as a container image and run it; no Go or Trivy on your machine.
- **Option B — From source:** You need **Go 1.21+** and **Trivy**. Use the **one-script install** for your OS so you don’t have to install them by hand.

---

## Install dependencies (from source)

If you want to build and run the scanner from source (instead of using the Docker image), run **one script** to install Go and Trivy:

| OS | Command (run from project root) |
|----|----------------------------------|
| **Linux** | `chmod +x scripts/install-deps.sh && ./scripts/install-deps.sh` (runs in background; use `--foreground` to wait) |
| **macOS** | Same as Linux |
| **Windows (PowerShell)** | `.\scripts\install-deps.ps1` (runs in background; use `-Foreground` to wait) |

The script installs Go and Trivy if they’re missing (using your package manager or a direct download). When it finishes, you can build and run the scanner. See [Help — What do I need installed?](HELP.md#what-do-i-need-installed) for more detail.

---

## Install the scanner

### Option A: Docker image (recommended for most users)

No Go or Trivy needed. From the project root:

```bash
docker build -t scanner:latest .
```

### Option B: Build from source

After running the [install-deps script](#install-dependencies-from-source) for your OS:

```bash
go build -o scanner ./cmd/cli
```

On Windows the binary will be `scanner.exe`. You can also use `go run ./cmd/cli` instead of building.

---

## First scan

1. **Make sure Docker is running** (so the scanner can pull or use local images). If you use only the Docker image, Docker is already required.
2. **Run a scan** against an image (e.g. `alpine:latest`):

   **Using the Docker image:**
   ```bash
   docker run --rm -v "$PWD/reports:/reports" scanner:latest scan --image alpine:latest --output-dir /reports --format sarif,markdown
   ```
   On Windows (cmd): use `%CD%\reports` instead of `$PWD/reports`.

   **Using the binary (from source):**
   ```bash
   ./scanner scan --image alpine:latest --output-dir ./reports
   ```
   On Windows: `.\scanner.exe scan --image alpine:latest --output-dir .\reports`

3. **Open the report**  
   Reports are written to the folder you gave (`./reports` or `/reports`). Open `report.md` (readable) or `report.html` in a browser. You also get `report.sarif` for Azure/GitHub Security. Reports include **Exploitable** (CISA KEV), **Why severity**, and **Exploit info**; see [Vulnerability reports](vulnerability-reports.md).

**Windows without PATH:** If Go and Trivy are not on your PATH, use `scripts\run-scan-local.bat` from the repo root (it uses Trivy/Go from known locations). Reports go to `reports\`.

---

## Updating the Trivy database (once a day)

For fresher vulnerability data, update Trivy’s database about once a day:

- **Linux/macOS:** Run `./scripts/update-trivy-db.sh` from the project root. To run daily automatically, add to crontab: `0 3 * * * /full/path/to/docker-scanner/scripts/update-trivy-db.sh`
- **Windows:** Run `.\scripts\update-trivy-db.ps1`. To run daily, use Task Scheduler and run that script. See [Help — Updating the Trivy database](HELP.md#updating-the-trivy-database-once-a-day).

---

## Next steps

- **[Help (plain language)](HELP.md)** — What is this? PATH, Trivy DB update, drag-and-drop, baseline and cleanup.
- [CLI reference](cli-reference.md) — All commands and flags.
- [CI/CD primer](ci-cd-primer.md) — Add the scanner to your pipeline.
- [Baseline](baseline.md) — Scan many images and get a summary + dashboard.
- [Troubleshooting](troubleshooting.md) — Common errors and fixes.
