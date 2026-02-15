# Help — In plain language

This page answers common questions in **simple terms**. If you’re new to the scanner or to container security, start here.

---

## What is this?

**Docker Container Scanner** is a tool that **checks a container image for known security problems** (vulnerabilities). It gives you a **report** that lists what it found and **how to fix each one** (for example: “Upgrade this package from version X to version Y”).

You can run it from the command line (CLI) or open the web page to get the exact command. It fits into your build pipeline (e.g. Azure, GitHub, GitLab, Jenkins) so every build can be checked automatically.

---

## What do I need installed?

It depends how you want to run the scanner:

- **Option 1 — Docker only:** You only need **Docker**. You build the scanner once as a container image, then run it and point it at any image you want to check. No Go or Trivy on your machine.
- **Option 2 — From source:** You need **Go** (version 1.21 or newer) and **Trivy**. The scanner uses Trivy under the hood to find vulnerabilities; Go is used to build and run the scanner.

**One script to install dependencies (Go + Trivy) on your machine:**

- **Linux or macOS:** From the project folder, run:  
  `./scripts/install-deps.sh`  
  (If you get “permission denied”, run: `chmod +x scripts/install-deps.sh` first.)
- **Windows (PowerShell):** From the project folder, run:  
  `.\scripts\install-deps.ps1`

The script installs Go and Trivy if they’re missing (using your system’s package manager or a direct download). After it finishes, you can build and run the scanner from source. If you prefer not to install anything, use **Option 1** and only install Docker; then you never need to run the install script.

---

## What do I do first?

1. **Choose how to run the scanner**  
   - **Easiest:** Use Docker. Install Docker, then build the scanner image once and run it (see [Getting started](getting-started.md)).  
   - **From source:** Run the [install-deps script](#what-do-i-need-installed) for your OS, then build and run the scanner.

2. **Run your first scan**  
   You give the scanner an image name (e.g. `alpine:latest` or `myapp:v1`). It looks up known vulnerabilities for the software inside that image and writes a report.

3. **Open the report**  
   You get files like `report.md` (readable), `report.html`, and `report.sarif` (for Azure/GitHub Security). Open the Markdown or HTML file to see what was found and how to fix it.

---

## What is a “baseline” run?

A **baseline** run means scanning **many images at once** (e.g. 100+ or a list you provide). The tool pulls each image (optional), scans it, and writes one summary report with **how many findings** and **how long each scan took** per image. You use it to see how your stack compares across many images or to test the scanner itself. The report includes CSV files and a **dashboard** (HTML with charts). See [Baseline](baseline.md) for how to run it and where the results go. After you’re done, you can free disk space by removing the pulled images using the [cleanup scripts](baseline.md#after-the-run-results-and-cleanup).

---

## Cleaning up after a baseline

If you ran a baseline with “pull before scan,” your machine will have downloaded many images. To free disk space:

- **Remove images from a specific run:**  
  `.\scripts\prune-baseline-run.ps1` (Windows) or use the latest CSV path. See [Baseline — After the run](baseline.md#after-the-run-results-and-cleanup).
- **Remove images pulled in the last N hours:**  
  `.\scripts\prune-images-last-hour.ps1 -Hours 6` (Windows). On Linux/macOS you can run the same logic or use `docker image prune -a`.
- **Remove all unused images:**  
  `docker image prune -a` (review the list before confirming).

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
- **Baseline** — Scanning many images in one run and getting a summary (findings count, duration per image) and optional dashboard. See [Baseline](baseline.md).

---

## I see an error. What do I do?

Go to [Troubleshooting](troubleshooting.md). There we list common errors, what they mean, and what to do step by step (e.g. “Trivy not found” → run the install-deps script or use the Docker image).

---

## Where do I find things?

| I want to… | Go here |
|------------|--------|
| Install dependencies (one script) | [What do I need installed?](#what-do-i-need-installed) above; [Getting started](getting-started.md) |
| Run my first scan | [Getting started](getting-started.md) |
| Understand every command and option | [CLI reference](cli-reference.md) |
| Scan a Dockerfile as well as the image | Use `--dockerfile path/to/Dockerfile`; see [CLI reference](cli-reference.md) |
| Add the scanner to my pipeline (Azure, GitHub, etc.) | [CI/CD primer](ci-cd-primer.md) |
| Run a baseline (many images) | [Baseline](baseline.md) |
| Clean up images after a baseline | [Baseline — After the run](baseline.md#after-the-run-results-and-cleanup); [Cleaning up](#cleaning-up-after-a-baseline) above |
| Fix an error | [Troubleshooting](troubleshooting.md) |
| Make the pipeline fail on Critical/High | Use `--fail-on-severity CRITICAL,HIGH`; see [CLI reference](cli-reference.md) |
| See how we compare to other scanners | [Comparison](COMPARISON.md) |
| Understand Exploitable, Why severity, CISA KEV | [Vulnerability reports](vulnerability-reports.md) |

---

## Who updates this?

The docs are kept in sync with the product. If something here doesn’t match what you see when you run the scanner, please report it or open a pull request.
