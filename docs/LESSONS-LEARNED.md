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
