# Comparison: Docker Container Scanner vs Other Scanners

Unbiased comparison of this project against free and paid container image scanners. Sources: public docs, GitHub, and comparison articles (2024–2025). Use this to see where we stand and what to enhance.

---

## Competitors overview

| Tool | Type | Cost | Maintainer |
|------|------|------|------------|
| **Trivy** | Open source | Free | Aqua Security |
| **Grype** | Open source | Free | Anchore |
| **Clair** | Open source | Free | Red Hat |
| **Snyk Container** | Commercial (free tier) | Free: 100 scans/mo; Team: ~$25/dev/mo; Enterprise: custom | Snyk |
| **Docker Scout** | Freemium | Free: 1 repo; paid for more | Docker |
| **Aqua Enterprise** | Commercial | Contact sales | Aqua Security |
| **Anchore / Syft** | Open source + commercial | Free (Grype/Syft); Enterprise: custom | Anchore |

---

## Feature comparison

| Feature | Our scanner | Trivy | Grype | Snyk | Docker Scout | Aqua Enterprise |
|--------|-------------|-------|-------|------|--------------|-----------------|
| **Image scan** | Yes (via Trivy) | Yes | Yes | Yes | Yes | Yes |
| **Rootfs / filesystem scan** | Yes (`--fs`, `--lxc` for LXC) | Yes (rootfs) | Yes (dir) | Varies | No | Varies |
| **Dockerfile scan** | Yes (`--dockerfile`) | Yes (config) | No | Yes | Yes | Yes |
| **SARIF output** | Yes | Yes | Via Syft/plugins | Yes | Yes | Yes |
| **Remediation text** | Yes (upgrade path + links) | Fixed version in JSON | Fixed version | Detailed + base image | Yes + base image | Yes + reachability |
| **CI/CD integration** | Yes (Azure, GitHub, GitLab, Jenkins) | Yes (native + actions) | Yes | Yes (native) | Yes (Docker ecosystem) | Yes |
| **Severity filter** | Yes | Yes | Yes | Yes | Yes | Yes |
| **Fail pipeline on severity** | Yes (`--fail-on-severity`, `--fail-on-count`) | Yes (`--exit-code 1`) | Yes | Yes | Yes (policy) | Yes (policy) |
| **Config file** | Yes (`scanner.yaml`, `.scanner.yaml`, `--config`) | Yes | Yes (`.grype.yaml`) | Yes | Yes | Yes |
| **Ignore / suppression** | Planned | Yes (VEX, Rego) | Yes (`.grype.yaml`) | Yes | Yes (policy) | Yes |
| **Offline mode** | Yes (`--offline`) | Yes | Yes | Limited | Limited | Yes |
| **Baseline / image comparison** | Yes (parallel baseline tool, `go run ./cmd/baseline`) | No (manual diff) | No | Custom base image (Enterprise) | Yes (image comparison) | Yes |
| **SBOM** | Yes (CycloneDX via `--sbom`) | Yes | Yes (Syft) | Yes | Yes | Yes |
| **Web UI** | Yes ✓ (`go run ./cmd/server` → browser scan with live SSE results) | No (CLI only) | No | Yes (dashboard) | Yes (Docker Hub) | Yes |
| **Base image recommendation** | In remediation text | No dedicated | No | Yes (incl. custom) | Yes (`recommendations`) | Yes |
| **Risk scoring beyond severity** | Yes (CISA KEV + OSV.dev + runc advisories) | CVSS | EPSS + KEV + composite | Yes | Health score (A–F) | Yes (reachability, etc.) |
| **Multi-scanner (IaC, secrets, licenses)** | No | Yes | Vuln only | Container + deps | Vuln + policy | Yes |

---

## Where we stand (unbiased)

### Strengths

1. **Remediation-first design** — We add explicit remediation text ("Upgrade X from Y to Z") and CVE links to every finding in SARIF/Markdown/HTML. Trivy and Grype expose fixed version in JSON but don't bundle a "remediation report" in the same way; we do.
2. **Multi-format report from one run** — SARIF (for Azure/GitHub Security tab) plus Markdown and HTML in one CLI invocation. Many setups use Trivy for SARIF and something else for human-readable; we unify that.
3. **CI-agnostic** — Same CLI and Docker image for Azure, GitHub, GitLab, Jenkins; examples and docs for each. We're not tied to one vendor.
4. **Offline from day one** — `--offline` and `--cache-dir` are first-class; good for air-gapped or locked-down CI.
5. **Baseline shipped** — `go run ./cmd/baseline` scans 100+ images in parallel with a summary CSV/Markdown and HTML dashboard. Differentiator vs plain Trivy/Grype; aligns with commercial tools.
6. **Web UI shipped** — `go run ./cmd/server` starts an HTTP server; paste or drop an image in the browser and get live scan results via SSE. Trivy and Grype are CLI-only. Aligns with Snyk/Docker Scout/Aqua.
7. **Risk scoring beyond CVSS** — CISA KEV (confirmed exploited = yes), OSV.dev back-fill (fills CVE IDs Trivy misses), runc host advisory (`--check-runtime`) for container escape CVEs. Goes further than Trivy default mode.

### Gaps vs competitors

1. ~~**No fail-on policy yet**~~ — **Done.** `--fail-on-severity` and `--fail-on-count`; exit 1 when policy violated. Matches Trivy/Grype/Snyk/Scout.
2. ~~**No config / ignore file**~~ — **Done (config).** `scanner.yaml` or `.scanner.yaml` (or `--config`) for default severity, format, output-dir, cache-dir, fail-on. **Ignore/suppression** (VEX, `.grype.yaml` equivalent) is still planned.
3. ~~**No Dockerfile scan yet**~~ — **Done.** `--dockerfile` runs Trivy config and merges misconfigurations with image findings.
4. ~~**No SBOM**~~ — **Done.** `--sbom` generates CycloneDX JSON for compliance and supply-chain tooling.
5. ~~**No risk scoring beyond severity**~~ — **Done.** CISA KEV, OSV.dev enrichment, and runc host advisory.
6. ~~**No Web UI**~~ — **Done.** `go run ./cmd/server` → browser, SSE streaming, findings table, export.
7. **Single engine** — We wrap Trivy only. Grype + Syft, or Trivy + Grype in one product, could improve coverage; that's a larger design choice.
8. **No commercial support** — Unlike Snyk, Docker Scout, Aqua, Anchore we're not a product with SLAs/support; we're an open project. That's a positioning choice, not a bug.

### Neutral / context

- **We're an orchestrator, not a CVE DB** — We rely on Trivy (and could add Grype). That's intentional: we focus on remediation, reports, CI, baseline, and Web UI rather than maintaining our own vulnerability database.
- **Market** — Trivy and Snyk have significant adoption; Docker Scout is bundled with Docker. We're a niche: "Trivy + remediation + multi-format report + multi-CI + baseline + Web UI."

---

## Enhancement recommendations (from comparison)

### Done ✓

1. ~~**Fail-on policy**~~ — **Done.** `--fail-on-severity` and `--fail-on-count`; exit 1 when policy violated.
2. ~~**Config file**~~ — **Done.** `scanner.yaml` / `.scanner.yaml` / `--config` for repeatable defaults.
3. ~~**Dockerfile scan**~~ — **Done.** `--dockerfile` merges Trivy misconfig findings with image findings.
4. ~~**SBOM export**~~ — **Done.** `--sbom` generates CycloneDX JSON via Trivy.
5. ~~**Risk scoring / exploited flag**~~ — **Done.** CISA KEV (`exploitable: yes`), OSV.dev CVE back-fill, runc host advisory (`--check-runtime`).
6. ~~**Web UI + server**~~ — **Done.** `go run ./cmd/server`; browser scan with SSE progress, findings table, severity filter, export (CSV/JSON/Markdown).
7. ~~**Baseline comparison**~~ — **Done (parallel baseline tool).** `go run ./cmd/baseline` scans 100+ images, outputs summary CSV/Markdown/HTML dashboard. Per-image diff vs a baseline image: planned.

### Still to do (roadmap)

8. **Ignore / suppression file** — Allowlist CVEs (and optionally packages) with optional expiry; report suppressed separately. Matches Trivy (VEX) and Grype (`.grype.yaml`).
9. **Base image recommendation (formalized)** — Suggest "Use base image X" when the vuln is in the base layer; formalize like Docker Scout `recommendations`.
10. **Optional second engine** — Allow Grype as an alternative or supplement to Trivy (different DB/coverage). Larger scope.

---

## Summary

| Dimension | Our position |
|-----------|----------------|
| **Remediation & report** | Strong: explicit remediation text + SARIF/MD/HTML/CSV in one run. |
| **CI integration** | Strong: same CLI/image for Azure, GitHub, GitLab, Jenkins. |
| **Offline** | Strong: first-class `--offline` and cache. |
| **Policy & fail-on** | Strong: `--fail-on-severity`, `--fail-on-count`, config file (`scanner.yaml`). Ignore/suppression file still planned. |
| **Dockerfile & SBOM** | Strong: Dockerfile scan (`--dockerfile`) and CycloneDX SBOM (`--sbom`). |
| **Baseline** | Strong: parallel tool ships; per-image diff is planned. |
| **Web UI** | Strong: live browser scan with SSE streaming, findings table, export. |
| **Risk scoring** | Strong: CISA KEV (exploitable), OSV.dev enrichment, runc host advisory. |

**Bottom line:** We're well placed as a "Trivy + remediation + multi-format + multi-CI + baseline + Web UI" orchestrator. The remaining gaps are ignore/suppression file (VEX/allowlist), formalized base image recommendations, and optional second scan engine.
