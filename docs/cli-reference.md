# CLI reference

## Commands

### scan

Scan a **container image** (Docker, Podman, containerd) or a **root filesystem** (e.g. LXC container). When `--dockerfile` is set (image scan only), the Dockerfile is scanned for misconfigurations. Produces SARIF, Markdown, and/or HTML reports with remediation.

**Image scan (Docker/Podman):**

```bash
scanner scan --image <ref> [options]
```

**Rootfs / LXC scan:**

```bash
scanner scan --fs <path> [options]
scanner scan --lxc <container_name> [options]   # Linux: uses /var/lib/lxc/<name>/rootfs
```

Use **either** `--image` **or** `--fs`/`--lxc`, not both. `--dockerfile` is only valid with `--image`.

| Flag | Description | Default |
|------|-------------|---------|
| `--image` | Image to scan (Docker/Podman/containerd). e.g. `alpine:latest`, `myregistry.io/app:v1` | (required if no --fs/--lxc) |
| `--fs` | Path to root filesystem to scan (e.g. LXC rootfs). Use instead of `--image` for filesystem/LXC. | (none) |
| `--lxc` | LXC container name: scan `/var/lib/lxc/<name>/rootfs` (Linux). Ignored if `--fs` is set. | (none) |
| `--dockerfile` | Path to Dockerfile; Trivy config is run on its directory. **Only with --image.** | (none) |
| `--severity` | Comma-separated: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN (default: all) | CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN |
| `--offline` | Skip DB update and OSV; use cache and embedded rules only | false |
| `--cache-dir` | Cache directory for Trivy DB | system default |
| `--output-dir` | Output directory for reports | ./reports |
| `--output-name` | Base name for report files (e.g. `report`) | report |
| `--timestamp` | Append timestamp to base name so each run writes unique files (e.g. `report-20060102-150405.html`) | false |
| `--format` | Comma-separated: sarif, markdown, html, csv | sarif,markdown |
| `--fail-on-severity` | Exit with code 1 if any finding has this severity (e.g. `CRITICAL,HIGH`). Empty = do not fail. Use in CI to gate the build. | (none) |
| `--fail-on-count` | Exit with code 1 if count for severity ≥ N. One rule only, format `SEVERITY:N` (e.g. `HIGH:5`). | (none) |
| `--config` | Path to config file. If omitted, scanner looks for `scanner.yaml` or `.scanner.yaml` in the current directory. | (none) |

**Fail-on policy:** Use `--fail-on-severity CRITICAL,HIGH` to fail the pipeline when any Critical or High finding exists. Use `--fail-on-count HIGH:5` to fail when there are 5 or more High findings. Exit code 1 prints a short reason and points to the report. Omit both flags to never fail (report only).

**Report content:** Markdown, HTML, and CSV include **Exploitable** (yes/no/unknown from CISA KEV), **Why severity**, and **Exploit info**. See [Vulnerability reports](vulnerability-reports.md).

**Progress display:** The CLI prints a single progress line to **stderr** (`Scanning <image>...` then `enriching...`); the baseline prints `Progress: N/total scanned` to stderr every second; the workflow test script shows `[ N/Total ] <image> done (findings)`. This is display-only and does not change how or when Trivy runs.

**Does progress add time to the scan?** Unbiased: **no meaningful time.** The progress UI only reads state and writes a short line to the terminal (a few bytes, a few times). The scan time is dominated by Trivy (network, DB, CPU). Progress updates are on the order of milliseconds; a typical scan is seconds to minutes. So the overhead is negligible (<0.1%). If you redirect stderr in CI, you get no progress and zero overhead.

### Config file

You can put default options in **`scanner.yaml`** or **`.scanner.yaml`** in the current directory (or pass `--config <path>`). CLI flags override config values. Use this in CI to avoid repeating `--severity`, `--format`, `--output-dir`, or `--fail-on-severity` on every run.

**Supported keys:** `severity`, `format`, `output-dir`, `output-name`, `cache-dir`, `fail-on-severity`, `fail-on-count`. Values are the same as the CLI (e.g. comma-separated for severity and format). No secrets; use only for paths and options.

Example (copy to `scanner.yaml` or `.scanner.yaml`):

```yaml
severity: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
format: sarif,markdown,html
output-dir: ./reports
output-name: report
# fail-on-severity: CRITICAL,HIGH
# fail-on-count: HIGH:5
```

See **`scanner.yaml.example`** in the repo root.

### db update

Update the vulnerability database (Trivy). Use when not in `--offline` mode to refresh the cache.

```bash
scanner db update [--cache-dir <dir>]
```

## Environment variables

- Registry auth: use Docker login (`docker login <registry>`) or env vars supported by the Docker/containerd client. The scanner does not accept credentials via env; use the standard Docker config.
- No secrets in config file or logs.
