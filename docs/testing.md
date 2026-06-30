# Testing

## Test types

| Type | Status | What it covers | Where |
|------|--------|----------------|-------|
| **Unit** | ✅ In place | Scanner JSON parsing (fixture-based), enrichment, SARIF/Markdown/HTML/CSV reports, policy evaluation, OSV client, runc advisories, CISA KEV client, config loader | `pkg/scanner`, `pkg/remediate`, `pkg/report`, `pkg/policy`, `pkg/osv`, `pkg/runc`, `pkg/kev`, `pkg/config` |
| **CLI exit-code** | ✅ In place | `runScan` returns 0/1 under `--fail-on-severity`, `--fail-on-count`, Trivy error; reports written to disk; LXC name validation | `cmd/cli/main_test.go` (fake Trivy binary) |
| **Enrichment integration** | ✅ In place | `Enrich()` + mock KEV server: exploit flag, severity upgrade to CRITICAL, ransomware text, offline mode; policy+enrichment pipeline end-to-end | `pkg/remediate/enrich_integration_test.go` |
| **Integration (full pipeline)** | ✅ In place | Full scan → enrich → report against real image (`alpine:3.10`) using Trivy. Gated by `integration` build tag. | `tests/integration/` |
| **Integration (config file)** | ✅ In place | Config-file-loaded options → scan → enrich → report | `tests/integration/scan_with_config_test.go` |
| **CI pipeline** | ✅ In place | `go vet` + `go test -race ./pkg/...` + `go build ./cmd/...` on every push/PR; integration scan on push to main | `.github/workflows/ci.yml` |
| **Baseline (manual)** | ✅ In place | 100+ images in parallel; CSV/Markdown/HTML dashboard | `go run ./cmd/baseline`; see [Baseline](baseline.md) |
| **Sanity checklist** | ✅ In place | Pre-PR/release: vet, build, unit tests, optional integration | [Sanity checklist](sanity.md) |
| **Baseline smoke (CI)** | 📋 Planned | Run baseline with `BASELINE_LIMIT=2` in CI to smoke-test the baseline code path | Not yet |
| **Install / script sanity** | 📋 Planned | Run `install-deps` then scan to catch PATH and script issues | Not yet |

---

## Unit tests

Unit tests cover all eight core packages. No Trivy or Docker required.

| Package | What is tested |
|---------|---------------|
| `pkg/kev` | Load, 24h cache TTL, cache expiry, HTTP errors, malformed JSON, concurrent safety (`-race`), `IsKnownExploited` case normalisation, `GetInfo` found/not-found, empty-ID skipping |
| `pkg/scanner` | JSON fixture parsing, severity distribution, `PkgPath` vs target `FilePath` fallback, remediation link order, severity filter, `scanRootfs` path validation, `GenerateSBOM` requires image |
| `pkg/remediate` | Remediation text generation, offline OSV skip, runc finding preservation, `whySeverityText`, CVE link injection, misconfig link injection |
| `pkg/report` | SARIF structural validation (required fields: `$schema`, `version`, `runs`, `tool.driver`, `result.ruleId/level/message`), location inclusion, rule deduplication, empty-findings SARIF; Markdown content; HTML escaping; CSV escaping; `WriteFindingsCSVWithImage` header/column order/RFC-4180 escaping |
| `pkg/policy` | `ParseFailOnCount`, `EvaluateFailPolicy` for severity, count, combined, edge cases |
| `pkg/osv` | Ecosystem mapping, HTTP mock, caching, error handling, CVE alias preference, multiple vulns |
| `pkg/runc` | `isVulnerable` semver comparison, advisory table integrity, `AdvisoryFindings` boundary cases, `HostVersion` via fake binary in PATH (docker JSON, fallback runc, malformed JSON, neither available) |
| `pkg/config` | YAML load, missing file, directory auto-detect |

```bash
# Run all unit tests with race detector
go test -race -count=1 ./pkg/...

# Run a specific package
go test -race ./pkg/kev/...
go test -race ./pkg/scanner/...
```

---

## CLI exit-code tests

These test the full `runScan()` function end-to-end using a fake `trivy` binary in a temp directory on PATH. No real Trivy or network required.

```bash
go test -race -count=1 ./cmd/cli/...
```

**Scenarios covered:**

| Test | Fake Trivy output | Policy | Expected exit code |
|------|-------------------|--------|-------------------|
| `TestRunScan_policyViolation_exitCode1` | 1 CRITICAL finding | `--fail-on-severity CRITICAL` | 1 |
| `TestRunScan_clean_exitCode0` | No findings | `--fail-on-severity CRITICAL` | 0 |
| `TestRunScan_trivyError_exitCode1` | exits 1 | — | 1 |
| `TestRunScan_failOnCount_exitCode1` | 1 CRITICAL | `--fail-on-count CRITICAL:1` | 1 |
| `TestRunScan_failOnCount_belowThreshold_exitCode0` | 1 CRITICAL | `--fail-on-count CRITICAL:5` | 0 |
| `TestRunScan_reportsWritten` | 1 CRITICAL | — | reports exist on disk |
| `TestValidLXCName` | — | — | path-traversal names rejected |

---

## Enrichment integration tests

These wire the real `Enrich()` function to a mock CISA KEV HTTP server to verify the exploit-flagging and severity-upgrade logic without touching the live endpoint.

```bash
go test -race -count=1 ./pkg/remediate/...
```

**Key assertions:**
- CVE in KEV → `Exploitable: "yes"`, `ExploitInfo` from `shortDescription`
- CVE in KEV with original severity HIGH → upgraded to `CRITICAL`
- CVE not in KEV → `Exploitable: "no"`
- `knownRansomwareCampaignUse: "Known"` → "ransomware" in `ExploitInfo`
- `offline: true` → `Exploitable: "unknown"`, KEV never called
- Policy pipeline: CRITICAL findings + `fail-on-severity=CRITICAL` → `shouldFail=true`
- Zero findings → no false policy trigger
- `fail-on-count` threshold arithmetic correct

---

## Integration tests (full pipeline)

Requires Trivy in PATH and network (Trivy DB + image pull on first run). Gated by `integration` build tag.

```bash
go test -tags=integration ./tests/integration/... -v
```

Scans `alpine:3.10` (known vulnerable). Trivy DB downloaded on first run.

---

## CI pipeline

Every push and PR runs:

```
go vet ./...
go test -race -count=1 ./pkg/...
go test -race -count=1 ./cmd/cli/...
go build ./cmd/cli ./cmd/server ./cmd/baseline
```

Integration scan (Trivy installed) runs on push to `main`. See `.github/workflows/ci.yml`.

---

## Oracle test fixture

`pkg/scanner/testdata/trivy-fixture.json` is a pinned Trivy JSON output for `alpine:3.10` with 5 known CVEs (3 CRITICAL, 1 HIGH, 1 MEDIUM). All fixture-based tests validate against this file. Update it only when deliberately changing the test baseline.

---

## Summary

| Kind | Command | Trivy / Docker |
|------|---------|----------------|
| Unit + race | `go test -race ./pkg/...` | Not required |
| CLI exit-code | `go test -race ./cmd/cli/...` | Not required (fake binary) |
| Enrichment integration | `go test -race ./pkg/remediate/...` | Not required (mock HTTP) |
| All (no integration) | `go test -race ./pkg/... ./cmd/cli/...` | Not required |
| Full integration | `go test -tags=integration ./tests/integration/...` | Trivy in PATH |
| Baseline (100+ images) | `go run ./cmd/baseline` | Trivy in PATH |
| Web UI | `go run ./cmd/server` → `http://localhost:8080` | Trivy in PATH; Docker running |
| Sanity (pre-PR) | See [Sanity checklist](sanity.md) | Go only; Trivy optional |

---

## Manual verification (config file, MCP, IDE)

No automated tests yet for (a) CLI with config file end-to-end, (b) MCP server calling `scan_image` with a real image, or (c) IDE extensions running a scan.

| What | How |
|------|-----|
| **Config file** | From a directory with `scanner.yaml`, run `scanner scan --image alpine:latest`. Confirm reports appear in `output-dir` from config and severity/format match the file. |
| **Web UI** | Run `go run ./cmd/server`. Open `http://localhost:8080`. Paste `alpine:latest`, click Scan. Verify: live SSE progress, summary cards, findings table, severity filter, CSV/JSON/Markdown export, error banner on bad image ref. |
| **MCP server** | Run `go run ./cmd/mcp-server`; connect MCP client; call `scan_image` with `{"image":"alpine:latest"}`; assert `ok: true` and `findings_count`/`report_dir` in JSON response. |
| **IDE extensions** | VS Code: F5 dev host → **Docker Scanner: Scan image** → enter `alpine:latest` → confirm Docker Scanner output channel. JetBrains: build plugin from `ide/jetbrains`, install from disk → **Tools → Scan image** → confirm Run window output. |
