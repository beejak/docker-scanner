# Lessons Learned

This file is updated by the **Lessons Learned Agent** after each significant task or milestone. Use it to review what worked, what didn’t, and what to do differently next time. **Only append; do not remove or rewrite past entries.**

---

## Template for new entries

```markdown
### [Task or milestone name]
- **When:** [Date or session]
- **What we did:** [1–2 sentences]
- **What worked:** [1–2 bullets]
- **What didn’t / was hard:** [1–2 bullets, or “Nothing significant”]
- **Score (1–5):** [1 = poor, 5 = great] — [one line reason]
- **Lesson / next time:** [One actionable takeaway]
```

---

## Entries

### Project setup and Phase A–C (core, Docker, CI)

- **When:** Initial build session
- **What we did:** Set up repo layout, Trivy integration, remediation enricher, SARIF/Markdown/HTML reports, Dockerfile, Azure/GitHub/GitLab/Jenkins CI examples and docs, agents, system design, roadmap, comparison.
- **What worked:** Single finding model and one report path kept enricher and report in sync; Trivy JSON parsing was straightforward; same CLI for all pipelines simplified CI docs.
- **What didn’t / was hard:** Go not in PATH in some environments (document Docker-first flow); SARIF rule deduping by CVE can miss per-package nuance.
- **Score (1–5):** 4 — Solid foundation and docs; fail-on and config file still missing for pipeline gates.
- **Lesson / next time:** Implement fail-on and config file early so CI users can gate on severity without custom scripting.

### Fail-on policy

- **When:** After roadmap "Next" prioritization (fail-on before Dockerfile scan).
- **What we did:** Added `--fail-on-severity` (exit 1 if any finding has listed severity) and `--fail-on-count SEVERITY:N` (exit 1 if count for severity >= N). Policy evaluated after report generation; clear stderr message and exit 1 so CI can gate the build.
- **What worked:** No new dependencies; logic in CLI only; single pass over findings by severity. Docs updated: CLI reference, troubleshooting (Policy violated), ROADMAP, COMPARISON.
- **What didn't / was hard:** Help.md glossary edit failed (special/curly quotes); added "Make the pipeline fail" row to Help table instead.
- **Score (1–5):** 5 — Delivers CI gates with minimal code; matches Trivy/Grype behavior.
- **Lesson / next time:** Keep Help glossary in ASCII quotes where possible to avoid replace failures; table links are sufficient for discoverability.

### Dockerfile scan

- **When:** Next roadmap item after fail-on policy.
- **What we did:** When `--dockerfile` is set, run `trivy config --format json` on the directory containing the Dockerfile; parse misconfigurations into the same Finding model (CVEID = check ID e.g. DS001, Package = target file, RemediationText = Resolution). Merge with image findings; enricher preserves existing RemediationText and adds AVD misconfig links for non-CVE IDs.
- **What worked:** Single Finding model for both vulns and misconfig; report and fail-on policy apply to merged list. Enricher skip when RemediationText already set and CVE vs misconfig link logic kept.
- **What didn't / was hard:** Trivy config expects a directory (we pass filepath.Dir(dockerfile)); no issues. Offline uses `--skip-policy-update` for config.
- **Score (1–5):** 5 — Straightforward; same report and policy path for image + Dockerfile.
- **Lesson / next time:** When adding a new finding source, map to the same Finding model and ensure enricher does not overwrite source-provided remediation (check RemediationText and link type).

### Security fixes (path traversal, HTTP timeout, CSV injection, image validation)

- **When:** Security audit session.
- **What we did:** Fixed four vulnerability classes: path traversal via `--lxc` (added `validLXCName` allowlist regex); insecure HTTP in KEV client (replaced `http.Get` with `http.Client{Timeout:30s}` + `io.LimitReader`); CSV injection in baseline output (`csvEscape()` helper wrapping fields in quotes when needed); missing image ref validation in baseline (`imageRefRE` regex before `docker pull`).
- **What worked:** Targeted surgical fixes; no API changes; existing tests continued to pass.
- **What didn't / was hard:** Nothing significant — each fix was isolated to one file.
- **Score (1–5):** 5 — All four OWASP-class vulnerabilities fixed with minimal code.
- **Lesson / next time:** Review all places that concatenate user input into shell commands, file paths, or CSV output at the start of any session — these are the most common classes.

### Detection priority, OSV enrichment, runc advisories, SBOM export

- **When:** Enhancement session (wild-vulnerability research + implementation).
- **What we did:** (1) Added `--detection-priority comprehensive` to both `scanImage` and `scanRootfs` so Trivy falls back to GitHub Advisory Database for Go/Java stdlib CVEs it misses in default mode. (2) Added `pkg/osv` — OSV.dev API client with in-process `sync.Map` cache and ordered ecosystem mapping (cargo/go substring collision fixed with slice-not-map). (3) Added `pkg/runc` — host runc version detection via `docker version` JSON or `runc --version`, advisory table for 4 critical container escape CVEs (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881, CVE-2024-21626), semver comparison. (4) Added `--sbom` flag — CycloneDX JSON via `trivy image --format cyclonedx`. (5) Wired OSV back-fill into enricher for findings with no CVE ID. (6) Added `--check-runtime` CLI flag that prepends runc advisory findings before enrichment. (7) Comprehensive unit tests (OSV: 11 tests; runc: 10 tests including boundary, edge, table integrity).
- **What worked:** Ordered slice for ecosystem rules immediately fixed the cargo/go collision; atomic semaphore pattern for one-scan-at-a-time kept both CLI and server safe; single Finding model meant runc/OSV findings flowed through enricher and all report formats unchanged.
- **What didn't / was hard:** `go vet ./cmd/...` failed on unrelated MCP server (missing go.sum entry) — scoped vet to only modified packages to unblock. Tag push blocked by server policy (HTTP 403); kept tag local only.
- **Score (1–5):** 5 — Four real differentiating features shipped in one session; all tests green with race detector.
- **Lesson / next time:** Always scope `go vet` and `go build` to modified packages when unrelated packages may have dependency issues. Use ordered slices (not maps) whenever iteration order affects substring matching.

### Web UI server with live SSE streaming

- **When:** Web UI implementation session.
- **What we did:** Built `cmd/server/main.go` — an HTTP server serving `web/index.html` at `/`, a `/api/scan` SSE endpoint streaming `{"type":"status"}` and `{"type":"complete"}` JSON events, and a `/health` liveness check. Atomic semaphore prevents concurrent scans. 10-minute context timeout. Input validation (image ref regex; absolute-path-only for fs). Rewrote `web/index.html` with a modern UI: dark navy header with custom SVG container logo, drop zone input, options row (mode/severity/check-runtime/offline), live progress log, summary stat cards, findings table with severity badges and NVD links, severity filter buttons, client-side CSV/JSON/Markdown export. Added `serve` target to Makefile. Added `## 🌐 Web UI` section to README with SSE flow diagram and feature table. Added executive reading guide and web UI background section to `docs/HELP.md`.
- **What worked:** SSE via `EventSource` API required no polling or WebSocket complexity; the `atomic.Bool` semaphore was clean and race-detector-safe; client-side export (Blob + URL.createObjectURL) kept the server stateless.
- **What didn't / was hard:** Stash/checkout conflict when switching branches (README had diverged between main and feature branch); resolved with `git checkout --theirs`. COMPARISON.md had "Planned" entries that were stale after shipping.
- **Score (1–5):** 5 — Full working browser UI with zero new dependencies; all existing unit tests pass with race detector.
- **Lesson / next time:** After shipping any roadmap item, immediately update COMPARISON.md "Planned" → "Done ✓" and the summary table. The stale entries mislead readers about the project's actual state.

### Testing strategy: filling critical coverage gaps

- **When:** Testing strategy session (Karpathy + QA engineer framing)
- **What we did:** Defined the "loss function" (zero false confidence — no silent scan failures), mapped the full gap surface across all 8 packages, then implemented: (1) `pkg/kev/kev_test.go` — 13 tests covering Load, 24h cache TTL, expiry, HTTP errors, malformed JSON, concurrent safety, `IsKnownExploited` case normalisation, `GetInfo`, empty-ID skipping. (2) Oracle fixture `pkg/scanner/testdata/trivy-fixture.json` — pinned alpine:3.10 Trivy JSON with 5 CVEs across severity levels. (3) `pkg/scanner/parse_test.go` — 9 fixture-based tests for parsing, severity distribution, FilePath resolution, severity filter, rootfs/SBOM error paths. (4) `pkg/runc` HostVersion tests — 5 tests using fake binaries in PATH. (5) SARIF structural validation — 8 tests for every field GitHub/Azure require. (6) `WriteFindingsCSVWithImage` — 4 tests (zero coverage → fully tested). (7) `pkg/remediate/enrich_integration_test.go` — 9 tests wiring real `Enrich()` to a mock KEV server. (8) Policy+enrichment pipeline tests — 4 tests covering the exact CLI decision path. (9) `cmd/cli/main_test.go` — 7 tests with fake Trivy binary for exit-code contract (`--fail-on-severity`, `--fail-on-count`, Trivy error). (10) `.github/workflows/ci.yml` — CI pipeline (was missing entirely). Refactored `runScan` to return int instead of calling `os.Exit` directly. Exported `SetURLForTest`/`ResetForTest` from `pkg/kev` for cross-package integration tests. Updated architecture-diagrams.md (network diagram, test coverage map, MCP/air-gapped topologies), testing.md (full rewrite), and sanity.md (added CLI test step and CI check note).
- **What worked:** The "oracle fixture" pattern — one pinned Trivy JSON file that all downstream tests validate against — gave a concrete shared baseline. The fake-binary-in-PATH pattern (from runc tests) scaled cleanly to CLI exit-code tests. Exporting thin test helpers (`SetURLForTest`, `ResetForTest`) from `pkg/kev` allowed cross-package integration tests without breaking encapsulation. Changing `runScan` to return int (instead of calling `os.Exit`) was a one-line refactor that made the entire CLI testable without subprocess overhead.
- **What didn't / was hard:** Go 1.21 doesn't support `for i := range N` (added in 1.22) — caught by compiler, fixed immediately. `const` → `var` for `cisaKEVURL` was required before tests could inject a mock URL. The `kev_test.go` (same package) and `enrich_integration_test.go` (external package) needed different reset strategies — internal `resetCache()` vs exported `ResetForTest()`.
- **Score (1–5):** 5 — Went from ~30% critical-path coverage to a complete, race-detector-clean test suite with no external dependencies for any unit/integration test. All 8 pkg/* packages + cmd/cli pass `-race -count=1`.
- **Lesson / next time:** Define the "oracle fixture" before writing any tests — a pinned, known-good input is the foundation every downstream test builds on. Change functions that call `os.Exit` to return int codes early; retrofitting is cheap and makes them immediately testable. Export minimal test helpers (`SetXForTest`, `ResetForTest`) rather than making internals public — keeps the production API clean while enabling cross-package test injection.

### Server, MCP, and baseline tests (filling the final cmd/* gaps)

- **When:** Follow-up testing session (continuing from previous).
- **What we did:** Added `cmd/server/main_test.go` (8 tests: handleHealth, buildSummary counts/empty, SSE input validation, concurrency guard, Content-Type header), `cmd/mcp-server/main_test.go` (6 tests: parseSeverities empty/custom/normalise, formatSummary empty/counts/order/unknown), `cmd/baseline/main_test.go` (7 tests: loadImages, csvEscape RFC-4180, writeFindingsMarkdown, writeDashboardHTML). Also resolved pre-existing go.sum blocker for mcp-server by running `go get github.com/modelcontextprotocol/go-sdk/mcp`.
- **What worked:** `httptest.NewRecorder` + manual SSE line parsing made server handler tests trivial — no real HTTP needed. Testing only pure helper functions in mcp-server (`parseSeverities`, `formatSummary`) sidestepped the SDK dependency entirely. `t.TempDir()` kept baseline output-file tests self-contained.
- **What didn't / was hard:** `go get` for mcp-server upgraded the Go toolchain from 1.21 to 1.25 (SDK requires >= 1.25); fortunately all existing tests remained green and all four binaries still built.
- **Score (1–5):** 5 — All `cmd/*` packages now have automated tests; full suite (pkg + cmd) passes `-race -count=1` with no external deps.
- **Lesson / next time:** Check third-party SDK minimum Go version before adding it to a module — a major toolchain upgrade can be an unexpected side-effect. Use `go mod graph | grep sdk` before `go get` to spot version requirements early.
