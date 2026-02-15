# Documentation Agent: checklist and triggers

This file is the **single source of truth** for the Documentation Agent. When any code, feature, CLI, or config changes, the agent updates the docs listed below. **Help and user-facing text must be understandable by a layman** (no jargon without explanation).

---

## Doc inventory (A–Z)

| Doc | Path | When to update |
|-----|------|----------------|
| **Comparison** | `docs/COMPARISON.md` | New feature that affects competitive position; new competitor info. |
| **CI – Azure** | `docs/ci/azure-devops.md` | CLI flags, scanner image, or pipeline steps change. |
| **CI – GitHub** | `docs/ci/github-actions.md` | Same. |
| **CI – GitLab** | `docs/ci/gitlab-ci.md` | Same. |
| **CI – Jenkins** | `docs/ci/jenkins.md` | Same. |
| **CI – README** | `docs/ci/README.md` | New pipeline type or high-level CI flow change. |
| **CLI reference** | `docs/cli-reference.md` | Any new/removed/changed command or flag; config file. |
| **Contributing** | `CONTRIBUTING.md` | Build steps, architecture, or agent changes. |
| **Getting started** | `docs/getting-started.md` | Install path, first-scan steps, or prerequisites. |
| **Help (layman)** | `docs/HELP.md` | Any user-facing flow, terms, or “what do I do?” content. |
| **Lessons learned** | `docs/LESSONS-LEARNED.md` | Updated by Lessons Learned Agent only (do not overwrite). |
| **README** | `README.md` | Features, quick start, project layout, or doc links. |
| **Roadmap** | `ROADMAP.md` | Item completed, added, or reprioritized. |
| **System design** | `docs/system-design.md` | New component, data flow, interface, or deployment. |
| **Troubleshooting** | `docs/troubleshooting.md` | New error, fix, or debug step. |

---

## Update triggers

- **New CLI flag or command** → CLI reference, Getting started (if user-facing), Help (if layman needs it), CI docs (if examples use it).
- **New feature (e.g. baseline, fail-on)** → README features, CLI reference, Roadmap (mark done), System design (if architecture changes), Comparison (if relevant).
- **Pipeline or CI change** → Relevant `docs/ci/*.md`, CI README.
- **New error or fix** → Troubleshooting.
- **Install or run steps change** → Getting started, README quick start, Help.
- **New doc** → Add to this checklist and to README/Help links.

---

## Layman-friendly help rules

- **Help section** (`docs/HELP.md`): Use simple language. Explain “what is this?”, “what do I do first?”, “what is a CVE / severity / SARIF?” in one sentence. No assumed knowledge of Docker or security jargon without a short explanation.
- **Getting started**: One clear path: “Do this, then this, then you get this.” Avoid branching until later sections.
- **CLI reference**: Each flag: what it does in plain English, default, example. For severity/baseline/SARIF, add a “What does this mean?” line or link to Help.
- **Troubleshooting**: “You see X → It means Y → Do Z.” Link to Help or CLI reference for details.
- **Errors in CLI**: When adding or changing error messages in code, use language a layman can understand; suggest one concrete fix and link to docs where possible.

---

## Agent instruction

**Documentation Agent:** The Cursor rule `documentation-agent.mdc` is **alwaysApply: true**, so the agent runs in context after any change. After any task that changes code, CLI, config, or behavior (including completion of a roadmap item), run through this checklist. Update every doc that is triggered (see table and triggers above). Keep Help and user-facing prose layman-friendly. Do not modify `docs/LESSONS-LEARNED.md` content (that is owned by the Lessons Learned Agent). The coder does not need to remember to update docs; the agent is responsible.
