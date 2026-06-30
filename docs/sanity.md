# Sanity checklist

Run these checks before opening a PR or cutting a release.

---

## Quick sanity (no Trivy/Docker)

From repo root:

| Step | Command | What it checks |
|------|---------|----------------|
| 1. Dependencies | `go mod tidy` | No missing or unused modules |
| 2. Vet | `go vet ./cmd/... ./pkg/...` | No suspicious code (unreachable code, wrong printf args) |
| 3. Build CLI | `go build -o scanner ./cmd/cli` | CLI compiles (Windows: `scanner.exe`) |
| 4. Build baseline | `go build -o baseline ./cmd/baseline` | Baseline compiles |
| 5. Build server | `go build -o scanner-server ./cmd/server` | Server compiles |
| 6. Unit tests + race | `go test -race -count=1 ./pkg/...` | All 8 packages: kev, scanner, osv, runc, remediate, report, policy, config |
| 7. CLI tests | `go test -race -count=1 ./cmd/cli/...` | Exit-code contract (`--fail-on-severity`, `--fail-on-count`), report output, LXC name validation |

All of the above require only **Go**; no Trivy or Docker.

---

## Full sanity (Trivy in PATH)

| Step | Command | What it checks |
|------|---------|----------------|
| 8. Integration | `go test -tags=integration ./tests/integration/... -v -count=1` | Full scan → enrich → report against `alpine:3.10` |

First run downloads the Trivy DB and image.

---

## CI check

After every push/PR the GitHub Actions workflow (`.github/workflows/ci.yml`) runs steps 2, 6, 7, and 3–5 automatically. Check the Actions tab before merging.

---

## Optional (manual)

- **One scan:** `./scanner scan --image alpine:latest --output-dir ./reports` then open `reports/report.md`.
- **SARIF import:** Upload `reports/report.sarif` to a GitHub repo Security tab; verify findings appear.
- **Baseline smoke:** `BASELINE_LIMIT=2 go run ./cmd/baseline` — completes in <60 s, writes CSV.
- **Web UI:** `go run ./cmd/server` → `http://localhost:8080` → paste `alpine:latest` → verify SSE progress, findings table, export buttons.
- **MCP server:** `go run ./cmd/mcp-server`; call `scan_image {"image":"alpine:latest"}`; assert `ok: true`.
- **Scripts:** `./scripts/install-deps.sh --foreground` on a clean machine; `./scripts/update-trivy-db.sh`.
