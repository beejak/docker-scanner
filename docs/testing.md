# Testing

## Test types (current and planned)

| Type | Status | What it does | Where |
|------|--------|--------------|--------|
| **Unit** | ✅ In place | Tests scanner (Trivy JSON → findings), remediate (enrichment), report (SARIF/MD/HTML), policy (fail-on-severity, fail-on-count) with mocks/fixtures. No Trivy or Docker. | `pkg/scanner`, `pkg/remediate`, `pkg/report`, `pkg/policy` |
| **Integration** | ✅ In place | Full pipeline (scan → enrich → report) against a real image (`alpine:3.10`) using Trivy. Gated by `integration` build tag. | `tests/integration/` |
| **Baseline (manual)** | ✅ In place | Scan many images (100+ or a list), get summary CSV/MD and dashboard. Run manually; not automated. | `go run ./cmd/baseline`; see [Baseline](baseline.md) |
| **Sanity checklist** | ✅ In place | Pre-PR/release: `go mod tidy`, `go vet`, build CLI + baseline, unit tests, optional integration. | [Sanity checklist](sanity.md) |
| **Baseline smoke (CI)** | 📋 Planned | Run baseline with a small limit (e.g. 2 images) in CI to ensure baseline code path and report generation work. Requires Trivy (and optionally Docker) in the runner. | Not yet; add job that runs baseline with `BASELINE_LIMIT=2` |
| **Install / script sanity** | 📋 Planned | In CI or nightly: run install-deps (or use Docker) and then run one scan to confirm “install → scan → report” works. Catches script and PATH issues. | Not yet; add job or document manual run |
| **KEV / enrichment** | 📋 Optional | Unit tests for CISA KEV lookup and “Exploitable” enrichment (e.g. mock HTTP or fixture). Currently `pkg/kev` has no test files. | `pkg/kev` |
| **E2E / CLI exit code** | 📋 Optional | Test CLI exit code and stderr for `--fail-on-severity` and `--fail-on-count` (e.g. run scanner with known-failing image and assert exit 1). | Not yet |

Use **unit** and **integration** for day-to-day development. Use the [sanity checklist](sanity.md) before PRs. Add **baseline smoke** and **install sanity** in CI when you set up workflows.

---

## Unit tests

Unit tests cover the scanner (Trivy JSON → findings), remediate (enrichment), report (SARIF/Markdown/HTML), and policy (fail-on-severity, fail-on-count). No Trivy or Docker required.

```bash
go test ./pkg/... -v
```

Run a specific package:

```bash
go test ./pkg/scanner/... -v
go test ./pkg/remediate/... -v
go test ./pkg/report/... -v
go test ./pkg/policy/... -v
```

## Integration tests

Integration tests run the full pipeline (scan → enrich → report) against a real image using Trivy. They are gated by the `integration` build tag so they are not run by default.

**Requirements**

- Go 1.21+
- [Trivy](https://trivy.dev/) in `PATH`
- Network (for Trivy DB update and image pull) unless you use `--offline` with a pre-populated cache

**Run integration tests**

```bash
go test -tags=integration ./tests/integration/... -v
```

The test uses image `alpine:3.10` (a known vulnerable base). Trivy will download the vulnerability DB on first run if not offline.

**In CI**

- Enable integration tests only when Trivy is installed (e.g. a dedicated job or step).
- Example: install Trivy, then `go test -tags=integration ./tests/integration/...`.

## Automated setup and test (Windows)

If Go or Trivy are not installed, you can run the setup script. It will:

1. Install Go (via winget, or download a portable zip into `.go/` in the repo)
2. Run `go mod tidy`, build the CLI, run unit tests
3. Install Trivy (via `go install` or download Windows zip into `.trivy/`)
4. Run integration tests

**From repo root:**

```powershell
.\scripts\setup-and-test.ps1
```

Or with execution policy bypass (if needed):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup-and-test.ps1
```

**Via Make (Windows):**

```bash
make setup-and-test
```

**Quick test run (when Go is already in PATH):**

```batch
scripts\run-tests.bat
```

Unit tests always run; integration tests run only if Trivy is in PATH.

## Windows without PATH

If you don’t want to add Go or Trivy to your user Path variable, use these scripts. They add the usual locations to PATH for that run only:

| Script | What it does |
|--------|----------------|
| `scripts\run-tests.bat` | Sets Trivy + Go from `Downloads\trivy_*` and `Program Files\Go\bin`, then runs unit and integration tests |
| `scripts\run-scan-local.bat` | Same PATH, then runs a local scan (default image `alpine:latest`); reports in `reports\` |
| `scripts\env-local.bat` | Sets PATH and keeps the window open so you can run other commands |

Paths used: Trivy `C:\Users\Master\Downloads\trivy_0.69.1_windows-64bit\Trivy`, Go `C:\Program Files\Go\bin`. Edit the batch files if your paths differ.

## Baseline (100+ images)

To check for **gaps in testing** and scanner behavior across many images, run the baseline: `go run ./cmd/baseline` from repo root. It scans 111 images (Alpine, Debian, Ubuntu, Busybox, Node, Python, Redis, Nginx, Postgres, etc.) in parallel and writes `test-results/baseline-YYYYMMDD-HHMMSS.csv` and `.md` with **Findings** and **Duration (s)** per image. Use this to spot images with many Critical/exploitable findings or slow scans. See [Baseline](baseline.md) and [Vulnerability reports](vulnerability-reports.md).

## Summary

| Kind           | Command                                      | Trivy / Docker |
|----------------|----------------------------------------------|----------------|
| Unit only      | `go test ./pkg/...`                          | Not required   |
| Integration    | `go test -tags=integration ./tests/integration/...` | Trivy in PATH; Docker optional |
| Baseline (100+ images) | `go run ./cmd/baseline` | Trivy in PATH; see [Baseline](baseline.md) |
| Sanity (pre-PR) | See [Sanity checklist](sanity.md) | Go required; Trivy optional for integration |
| Setup + all    | `scripts\setup-and-test.ps1` (Windows)      | Installs Go + Trivy if missing |
| Windows no PATH | `scripts\run-tests.bat` or `scripts\run-scan-local.bat` | Uses Trivy/Go from known paths |
