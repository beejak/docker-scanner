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
