# Troubleshooting

## Common errors

### "trivy: executable file not found"

**Cause:** Trivy is not installed or not in PATH.

**Fix:**
- Install Trivy: see [Trivy installation](https://trivy.dev/latest/docs/installation/). Example (Linux/macOS): `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
- Or run the [install-deps script](getting-started.md#install-dependencies-from-source) for your OS, or run the scanner via Docker: `docker run --rm -v $(pwd)/reports:/reports scanner:latest scan --image <ref> --output-dir /reports` (the scanner image includes Trivy).
- If Trivy is installed but not in PATH, see [Help — Adding tools to your PATH](HELP.md#adding-tools-to-your-path).

### "Could not pull image" / "unauthorized"

**Cause:** Registry auth failed (private image or baseline image).

**Fix:**
- Run `docker login <registry>` (e.g. `docker login dhi.io` for Docker Hardened Images).
- In CI, use a service connection (Azure), secrets (GitHub/GitLab), or Jenkins credentials and log in before the scan step.

### "Scan failed: context deadline exceeded"

**Cause:** Scan timed out (large image or slow network).

**Fix:**
- Increase timeout if the scanner supports it (future: `--timeout`).
- Use `--severity CRITICAL,HIGH` for a faster fail-fast pass.
- Ensure cache is populated (`scanner db update` or run once without `--offline`) so subsequent runs are faster.

### Out of memory

**Cause:** Very large image or many layers.

**Fix:**
- Increase memory for the CI job or container.
- Use a smaller base image for your app when possible.

### "Policy violated" / exit code 1

**Cause:** You used `--fail-on-severity` or `--fail-on-count` and the scan results broke that rule (e.g. at least one Critical finding, or 5+ High findings).

**Fix:**
- Open the report in `--output-dir` and fix the listed findings (upgrade packages, change base image, etc.), then run the scan again.
- Or relax the policy: use fewer severities in `--fail-on-severity` (e.g. only `CRITICAL`) or a higher count in `--fail-on-count` (e.g. `HIGH:10`). Remove the flag(s) to never fail and only produce reports.

### "dockerfile not found" or "parse trivy config json" error

**Cause:** The path passed to `--dockerfile` does not exist, or Trivy config output format changed.

**Fix:**
- Ensure the path is correct (relative to current directory or absolute). Example: `--dockerfile ./Dockerfile` or `--dockerfile /path/to/Dockerfile`.
- Trivy config scans the **directory** containing the Dockerfile; the scanner passes the parent directory to Trivy. Ensure the file exists and Trivy supports scanning it.
- If the error is "parse trivy config json", ensure your Trivy version is compatible; run `trivy config --format json .` manually in the same directory to check output.

### "Failed to acquire cache or database lock" / "cache may be in use by another process: timeout"

**Cause:** Multiple Trivy processes are using the same cache directory at once. This often happens when running the **baseline** (many images in parallel): all workers shared the default Trivy cache and contended for a single lock.

**Fix:**
- The baseline command now uses a **per-worker cache dir** (`test-results/trivy-cache-baseline/w0`, `w1`, …) so parallel scans do not contend. Re-run `go run ./cmd/baseline` with the updated code.
- If you run multiple scanner or Trivy processes yourself (e.g. several `trivy image` in parallel), give each a separate cache: `TRIVY_CACHE_DIR=/path/to/cache1 trivy image ...` and use a different path per process. Or run scans sequentially (one worker).

### "parse trivy json" error

**Cause:** Trivy output format changed or Trivy failed and wrote an error message instead of JSON.

**Fix:**
- Ensure Trivy version is compatible (scanner is tested with recent Trivy).
- Run `trivy image --format json <image>` manually and check output.
- Run without `--offline` once to refresh the DB in case of corruption.
- For fresher vulnerability data, run the [Trivy DB update script](HELP.md#updating-the-trivy-database-once-a-day) about once a day: `./scripts/update-trivy-db.sh` (Linux/macOS) or `.\scripts\update-trivy-db.ps1` (Windows).

### I want to test with an image that has many vulnerabilities

Use an image built for scanner testing so you can stress-test reports and CI:

- **MaxCVE** (Chainguard): `ghcr.io/chainguard-dev/maxcve/maxcve:latest` — tens of thousands of findings; scan takes 1–2 minutes. Good for testing report generation, SARIF size, and fail-on policy.

```bash
scanner scan --image ghcr.io/chainguard-dev/maxcve/maxcve:latest --output-dir ./reports --format sarif,markdown,html
```

### Why do I only see one (or few) findings? Is the rest of the image clean?

**Cause:** The scanner does **not** filter to one severity. By default it asks Trivy for **CRITICAL, HIGH, MEDIUM, LOW** and reports every finding Trivy returns. A low count means Trivy’s vulnerability DB currently has that many matching CVEs for the packages in that image—not that other severities were dropped.

**Check:**
- Run Trivy directly to compare: `trivy image <your-image>` (or `trivy image --format json <image>`). The count should match.
- Default is **all** severities (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN). To restrict (e.g. fail-fast), use `--severity CRITICAL,HIGH`.

## Debug logging

Future: the scanner will support `--debug` or `LOG_LEVEL=debug` for verbose output. For now, run Trivy directly to see full output:

```bash
trivy image --format json <your-image>
```

## Offline mode

- Use `--offline` when no network is available. The vulnerability DB must already be in the cache (run once with network, or use a pre-populated cache volume in CI).
- In offline mode, remediation uses only Trivy data and embedded rules; no OSV or other network calls.
