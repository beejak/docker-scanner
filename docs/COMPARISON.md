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
| **Dockerfile scan** | Yes (`--dockerfile`) | Yes (config) | No | Yes | Yes | Yes |
| **SARIF output** | Yes | Yes | Via Syft/plugins | Yes | Yes | Yes |
| **Remediation text** | Yes (upgrade path + links) | Fixed version in JSON | Fixed version | Detailed + base image | Yes + base image | Yes + reachability |
| **CI/CD integration** | Yes (Azure, GitHub, GitLab, Jenkins) | Yes (native + actions) | Yes | Yes (native) | Yes (Docker ecosystem) | Yes |
| **Severity filter** | Yes | Yes | Yes | Yes | Yes | Yes |
| **Fail pipeline on severity** | Yes (`--fail-on-severity`, `--fail-on-count`) | Yes (`--exit-code 1`) | Yes | Yes | Yes (policy) | Yes (policy) |
| **Config file** | Yes (`scanner.yaml`, `.scanner.yaml`, `--config`) | Yes | Yes (`.grype.yaml`) | Yes | Yes | Yes |
| **Ignore / suppression** | Planned | Yes (VEX, Rego) | Yes (`.grype.yaml`) | Yes | Yes (policy) | Yes |
| **Offline mode** | Yes (`--offline`) | Yes | Yes | Limited | Limited | Yes |
| **Baseline / image comparison** | Planned | No (manual diff) | No | Custom base image (Enterprise) | Yes (image comparison) | Yes |
| **SBOM** | No | Yes | Yes (Syft) | Yes | Yes | Yes |
| **Web UI** | Planned | No (CLI only) | No | Yes (dashboard) | Yes (Docker Hub) | Yes |
| **Base image recommendation** | In remediation text | No dedicated | No | Yes (incl. custom) | Yes (`recommendations`) | Yes |
| **Risk scoring beyond severity** | No | CVSS | EPSS + KEV + composite | Yes | Health score (A–F) | Yes (reachability, etc.) |
| **Multi-scanner (IaC, secrets, licenses)** | No | Yes | Vuln only | Container + deps | Vuln + policy | Yes |

---

## Where we stand (unbiased)

### Strengths

1. **Remediation-first design** — We add explicit remediation text (“Upgrade X from Y to Z”) and CVE links to every finding in SARIF/Markdown/HTML. Trivy and Grype expose fixed version in JSON but don’t bundle a “remediation report” in the same way; we do.
2. **Multi-format report from one run** — SARIF (for Azure/GitHub Security tab) plus Markdown and HTML in one CLI invocation. Many setups use Trivy for SARIF and something else for human-readable; we unify that.
3. **CI-agnostic** — Same CLI and Docker image for Azure, GitHub, GitLab, Jenkins; examples and docs for each. We’re not tied to one vendor.
4. **Offline from day one** — `--offline` and `--cache-dir` are first-class; good for air-gapped or locked-down CI.
5. **Planned baseline and DHI** — Roadmap includes baseline comparison and Docker Hardened Images (digest/attestation). That’s a differentiator vs plain Trivy/Grype; Snyk/Docker Scout have similar ideas (image comparison, base image recommendations).
6. **Planned Web UI** — Trivy and Grype are CLI-only; we plan a UI for non-CLI users, which aligns with Snyk/Docker Scout/Aqua.

### Gaps vs competitors

1. **No fail-on policy yet** — Trivy has `--exit-code 1 --severity CRITICAL`; we don’t. This is the top “must have” for pipeline gates.
2. **No Dockerfile scan yet** — Trivy config, Snyk, Docker Scout scan Dockerfiles; we only scan the image. Implementing `--dockerfile` closes a clear gap.
3. **No config / ignore file** — Trivy and Grype support config and ignore rules; we don’t yet. Teams need repeatable policy (config) and suppressions (ignore file with expiry).
4. **No SBOM** — We don’t emit SBOM (CycloneDX/SPDX). Trivy, Grype/Syft, Snyk, Docker Scout do. SBOM is increasingly required for compliance and supply-chain tooling.
5. **No risk scoring beyond severity** — Grype has EPSS/KEV; Docker Scout has health scores; Snyk has prioritization. We only have severity; adding a simple risk score or “exploited” flag would help prioritization.
6. **Single engine** — We wrap Trivy only. Grype + Syft, or Trivy + Grype in one product, could improve coverage; that’s a larger design choice.
7. **No commercial support** — Unlike Snyk, Docker Scout, Aqua, Anchore we’re not a product with SLAs/support; we’re an open project. That’s a positioning choice, not a bug.

### Neutral / context

- **We’re an orchestrator, not a CVE DB** — We rely on Trivy (and could add Grype). That’s intentional: we focus on remediation, reports, CI, and (later) baseline/UI rather than maintaining our own vulnerability database.
- **Market** — Trivy and Snyk have significant adoption; Docker Scout is bundled with Docker. We’re a niche: “Trivy + remediation + multi-format report + multi-CI + (planned) baseline and UI.”

---

## Enhancement recommendations (from comparison)

### High impact (do soon)

1. ~~**Fail-on policy**~~ — **Done.** `--fail-on-severity` and `--fail-on-count`; exit 1 when policy violated. Matches Trivy/Grype/Snyk/Scout.
2. **Config file** — Done. `scanner.yaml` or `.scanner.yaml` (or `--config`) for default severity, format, output-dir, cache-dir, fail-on. Matches Trivy/Grype and reduces CI repetition.
3. **Ignore / suppression file** — Allowlist CVEs (and optionally packages) with optional expiry; report suppressed separately. Matches Trivy (VEX) and Grype (`.grype.yaml`).
4. ~~**Dockerfile scan**~~ — **Done.** When `--dockerfile` is set, run Trivy config and merge misconfigurations with image findings.

### Medium impact (roadmap)

5. **Baseline comparison** — `--baseline-image`, diff report, fail on delta. Differentiator vs plain Trivy/Grype; aligns with Docker Scout “image comparison” and Snyk base image recommendations.
6. **SBOM export** — Optional CycloneDX or SPDX (e.g. from Trivy or Syft) for compliance and supply-chain tools.
7. **Web UI + server** — UI for non-CLI users; same logic as CLI. Aligns with Snyk/Scout/Aqua; Trivy/Grype don’t offer this.
8. **Base image recommendation** — In remediation, suggest “Use base image X” when the vuln is in the base layer (we have partial text; could formalize like Docker Scout `recommendations`).

### Nice to have

9. **Risk score or “exploited” flag** — Use EPSS/KEV (e.g. from Grype or a small integration) to surface “known exploited” or a 0–10 score. Helps prioritization like Grype/Scout.
10. **Optional second engine** — Allow Grype as an alternative or supplement to Trivy (different DB/coverage). Larger scope; only if we want to compete on coverage.

---

## Summary

| Dimension | Our position |
|-----------|----------------|
| **Remediation & report** | Strong: explicit remediation text + SARIF/MD/HTML in one run. |
| **CI integration** | Strong: same CLI/image for Azure, GitHub, GitLab, Jenkins. |
| **Offline** | Strong: first-class `--offline` and cache. |
| **Policy & fail-on** | Weak: no fail-on or config/ignore yet — implement soon. |
| **Dockerfile & SBOM** | Gap: add Dockerfile scan and optional SBOM. |
| **Baseline & UI** | Planned: differentiator if we ship; aligns with commercial tools. |
| **Risk scoring** | Gap: severity only; EPSS/KEV would help. |

**Bottom line:** We’re well placed as a “Trivy + remediation + multi-format + multi-CI” orchestrator with a path to baseline and UI. To be competitive with Trivy/Grype in pipelines, add **fail-on**, **config**, and **ignore file** next; then **Dockerfile scan** and **baseline**. SBOM and risk scoring round out the picture for compliance and prioritization.
