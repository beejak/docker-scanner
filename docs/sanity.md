# Sanity checklist

Run these checks before opening a PR or cutting a release to ensure the repo is in good shape.

---

## Quick sanity (no Trivy/Docker)

From repo root:

| Step | Command | What it checks |
|------|---------|----------------|
| 1. Dependencies | `go mod tidy` | No missing or unused modules |
| 2. Vet | `go vet ./cmd/... ./pkg/...` | No suspicious code (e.g. unreachable code, wrong printf args) |
| 3. Build CLI | `go build -o scanner ./cmd/cli` | CLI compiles (Windows: `scanner.exe`) |
| 4. Build baseline | `go build -o baseline ./cmd/baseline` | Baseline compiles |
| 5. Unit tests | `go test ./pkg/... -v -count=1` | Scanner, remediate, report, policy logic |

All of the above require only **Go**; no Trivy or Docker.

---

## Full sanity (Trivy in PATH)

If Trivy is in PATH (and optionally Docker for image pull):

| Step | Command | What it checks |
|------|---------|----------------|
| 6. Integration test | `go test -tags=integration ./tests/integration/... -v -count=1` | Full scan → enrich → report against a real image (`alpine:3.10`) |

First run may download the Trivy DB and the image.

---

## Optional (manual)

- **One scan:** Run `./scanner scan --image alpine:latest --output-dir ./reports` (or use the Docker image) and open `reports/report.md` to confirm output.
- **Baseline smoke:** Run baseline with a tiny list and limit, e.g. `BASELINE_LIMIT=2 BASELINE_IMAGES=tests/baseline/images-lesser-known.txt go run ./cmd/baseline` (requires Trivy; use `BASELINE_PULL_FIRST=1` and `BASELINE_DELAY_SEC=10` if you hit rate limits).
- **Scripts:** Run `./scripts/install-deps.sh --foreground` or `.\scripts\install-deps.ps1 -Foreground` on a clean(ish) machine to confirm install path; run `./scripts/update-trivy-db.sh` or `.\scripts\update-trivy-db.ps1` to confirm Trivy DB update.

---

## CI

A future CI workflow can run steps 1–5 on every push, and step 6 in a job that has Trivy installed. See [Test types (current and planned)](testing.md#test-types-current-and-planned) and [CI/CD primer](ci-cd-primer.md).
