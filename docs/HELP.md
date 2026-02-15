# Help — In plain language

This page answers common questions in **simple terms**. If you’re new to the scanner or to container security, start here.

---

## What is this?

**Docker Container Scanner** is a tool that **checks a container image for known security problems** (vulnerabilities). It gives you a **report** that lists what it found and **how to fix each one** (for example: “Upgrade this package from version X to version Y”).

You can run it from the command line (CLI) or, in the future, from a web page. It fits into your build pipeline (e.g. Azure, GitHub, GitLab, Jenkins) so every build can be checked automatically.

---

## What do I do first?

1. **Install or run the scanner**  
   Easiest: use Docker. Build the scanner image once, then run it and point it at an image you want to check (e.g. `alpine:latest`).  
   See [Getting started](getting-started.md) for exact commands.

2. **Run your first scan**  
   You give it an image name (e.g. `alpine:latest` or `myapp:v1`). The scanner looks up known vulnerabilities for the software inside that image and writes a report.

3. **Open the report**  
   You get files like `report.md` (readable) and `report.sarif` (for Azure/GitHub Security). Open the Markdown file to see what was found and how to fix it.

---

## What do the words mean?

- **Image** — A snapshot of an application and its dependencies (like a recipe + ingredients). Docker runs “containers” from images.
- **Vulnerability / CVE** — A known security flaw in a piece of software. “CVE” is the ID (e.g. CVE-2024-1234) used worldwide to refer to it.
- **Severity** — How serious a vulnerability is: **Critical**, **High**, **Medium**, **Low**. The scanner can filter by these (e.g. show only Critical and High). Findings that are **known to be exploited** (CISA KEV) are treated as Critical so you prioritize them.
- **Exploitable** — Whether the CVE is in the **CISA Known Exploited Vulnerabilities** catalog: **yes** (prioritize), **no**, or **unknown** (e.g. offline). See [Vulnerability reports](vulnerability-reports.md).
- **Why severity / Exploit info** — Short explanation of why the finding has that severity and how it can be exploited (from CISA KEV when available).
- **Remediation** — How to fix it. For example: “Upgrade package X from version 1.0 to 1.1.”
- **SARIF** — A standard format for security results. Azure DevOps and GitHub can show SARIF results in their “Security” tab.
- **Offline mode** — Running the scanner without the internet. You use a previously downloaded database of vulnerabilities (useful in locked-down or air-gapped environments).
- **Baseline** — (Planned) Comparing your image to a “reference” image (e.g. an official one) and only reporting problems that are *worse* than the baseline.

---

## I see an error. What do I do?

Go to [Troubleshooting](troubleshooting.md). There we list common errors, what they mean, and what to do step by step (e.g. “Trivy not found” → install Trivy or use the Docker image).

---

## Where do I find things?

| I want to… | Go here |
|------------|--------|
| Install and run my first scan | [Getting started](getting-started.md) |
| Understand every command and option | [CLI reference](cli-reference.md) |
| Scan a Dockerfile as well as the image | Use `--dockerfile path/to/Dockerfile`; see [CLI reference](cli-reference.md) |
| Add the scanner to my pipeline (Azure, GitHub, etc.) | [CI/CD primer](ci-cd-primer.md) |
| Fix an error | [Troubleshooting](troubleshooting.md) |
| Make the pipeline fail on Critical/High | Use `--fail-on-severity CRITICAL,HIGH`; see [CLI reference](cli-reference.md) |
| See how we compare to other scanners | [Comparison](COMPARISON.md) |
| Understand Exploitable, Why severity, CISA KEV | [Vulnerability reports](vulnerability-reports.md) |
| See what’s done and what’s next | [ROADMAP](../ROADMAP.md) (in project root) |

---

## Who updates this?

The **Documentation Agent** keeps all docs (including this Help page) up to date when we change the product. If something here doesn’t match what you see when you run the scanner, that’s a bug in our docs — please report it or open a pull request.
