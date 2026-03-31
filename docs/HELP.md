# Help — In plain language

This page answers common questions in **simple terms**. If you’re new to the scanner or to container security, start here.

---

## How the workflow runs (in short)

1. **You run** the scanner (CLI, Docker, IDE, or MCP) with an image name (and optional Dockerfile path).
2. **Config (optional):** If there is a `scanner.yaml` or `.scanner.yaml` in the current directory (or you pass `--config <path>`), the scanner loads default options (severity, format, output-dir, fail-on, etc.). Any flags you pass **override** the config.
3. **Scan:** The scanner runs **Trivy** on the image (and, if you set `--dockerfile`, on the Dockerfile for misconfigurations). Trivy returns a list of findings (CVEs, versions, severity).
4. **Enrich:** The scanner adds **remediation** (how to fix), **Exploitable** (CISA KEV), and **Why severity** to each finding.
5. **Report:** It writes the results to files in the output directory (SARIF, Markdown, HTML, CSV—depending on `--format`). If you used `--fail-on-severity` or `--fail-on-count`, it may exit with code 1 so your pipeline fails.

So: **run → (config) → Trivy scan → enrich → write reports (and optionally fail)**.

You can scan **container images** (Docker, Podman, containerd) with `--image <ref>`, or a **root filesystem** (e.g. an LXC container) with `--fs <path>` or `--lxc <name>` (Linux). See [Runtimes](#runtimes-podman-lxc) below.

---

## Runtimes (Podman, LXC)

- **Podman:** The scanner uses Trivy, which can use Podman when the Podman socket is available. If you see "no podman socket found" or similar, start the Podman socket (e.g. `systemctl --user enable --now podman.socket` on Linux) and ensure the image was pulled with Podman. Then run `scanner scan --image <ref>` as usual.
- **LXC (rootfs):** To scan an LXC container’s filesystem (packages inside the container), use **`--fs /var/lib/lxc/<container_name>/rootfs`** or, on Linux, **`--lxc <container_name>`** (which resolves to that path). You cannot use `--dockerfile` with rootfs scans. On Windows, LXC is uncommon; use `--fs` with the path to an exported or copied rootfs if you have one.

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

The script runs **in the background by default** so you can keep using your terminal. It writes a log file (`install-deps.log` in the project folder). To run it in the foreground and wait for it to finish, use:

- **Linux/macOS:** `./scripts/install-deps.sh --foreground`
- **Windows:** `.\scripts\install-deps.ps1 -Foreground`

After it finishes, you can build and run the scanner from source. If you prefer not to install anything, use **Option 1** and only install Docker; then you never need to run the install script.

---

## Adding tools to your PATH

If Go or Trivy were installed by the script to a folder under the project (e.g. `.go/go/bin` or `.trivy/...`), they might not be in your **PATH** in new terminals. PATH is the list of folders your system searches when you type a command.

- **Windows:**  
  - **Temporary (current session):** In PowerShell run  
    `$env:Path = "C:\path\to\docker-scanner\.go\go\bin;C:\path\to\docker-scanner\.trivy\...;$env:Path"`  
    (replace with the actual paths the install script printed.)  
  - **Permanent:** Open **System** → **Advanced system settings** → **Environment Variables**. Under “User variables” or “System variables”, select **Path** → **Edit** → **New**, and add the folder that contains `go.exe` and the folder that contains `trivy.exe`. OK out. New terminals will then find `go` and `trivy`.

- **Linux / macOS:**  
  Add to your shell config file (e.g. `~/.bashrc` or `~/.zshrc`):  
  `export PATH="/path/to/docker-scanner/.go/go/bin:/path/to/docker-scanner/.trivy/...:$PATH"`  
  (use the paths the install script printed.) Then run `source ~/.bashrc` (or open a new terminal).

---

## Updating the Trivy database (once a day)

Trivy uses a **vulnerability database** that is updated regularly. For fresher results, update it about **once a day**:

- **Linux/macOS:** Run `./scripts/update-trivy-db.sh` (from the project root). To run it automatically every day, add a **cron** job:  
  `0 3 * * * /full/path/to/docker-scanner/scripts/update-trivy-db.sh`  
  (e.g. run `crontab -e` and add that line; 3:00 AM daily.)
- **Windows:** Run `.\scripts\update-trivy-db.ps1`. To run it automatically every day, use **Task Scheduler**: create a daily task that runs  
  `powershell -File "C:\path\to\docker-scanner\scripts\update-trivy-db.ps1"`.

---

## Web UI — scan from the browser

The scanner ships a real web interface so you can scan images without touching the command line.

**Start the server:**
```bash
go run ./cmd/server       # listens on http://localhost:8080
# or
make serve                # same thing via the Makefile
PORT=9090 make serve      # custom port
```

**Then open `http://localhost:8080` in your browser.**

Paste or drop an image reference (`alpine:latest`, `nginx:1.24`, `ghcr.io/org/app:v2`) into the input box and press **Scan**. The server runs the full scan pipeline in the background and streams progress to your browser in real time. When the scan finishes you see:

- **Summary cards** — Total, Critical, High, Medium, Low, and Exploitable counts
- **Findings table** — CVE ID (linked to NVD), package, installed version, fixed version, severity badge, exploitable flag, remediation text
- **Severity filter buttons** — narrow to Critical, High, Medium, or Low with one click
- **Export buttons** — download results as CSV, JSON, or Markdown

**Options (shown in the UI):**
| Option | What it does |
|--------|-------------|
| Mode | Image (Docker/Podman) or Filesystem path |
| Severity filter | Limit results to Critical &amp; High only, Critical only, or all |
| Check host runc | Also test whether your container runtime has known escape CVEs |
| Offline | Use cached Trivy DB; skip OSV.dev network calls |

**What’s happening in the background:**

1. Your browser sends a GET request to `/api/scan?image=<ref>&severity=...` and opens an **EventSource** (Server-Sent Events) connection.
2. The server spawns a Trivy scan process against the image reference you provided — exactly what `scanner scan --image <ref>` does from the CLI.
3. Status messages stream back to your browser as JSON events: `{"type":"status","message":"Running Trivy..."}`.
4. After Trivy returns raw findings (JSON), the enricher adds remediation text, CISA KEV exploit status, OSV.dev CVE back-fill, and "Why severity" text.
5. The server sends a final `{"type":"complete","findings":[...],"summary":{...}}` event.
6. Your browser renders the summary cards and findings table — no page reload, no polling.

Only one scan runs at a time (the server uses an atomic semaphore). If you hit Scan while one is already running, you’ll see a "scan in progress" message.

**Requires:** Go + Trivy in PATH (same as the CLI). Docker must be running so Trivy can pull the image if it isn’t already cached locally.

---

## Reading a scan report as an executive

You don't need to understand every line of a vulnerability report. Here is what to look at first, in plain language.

### The one number that matters most: Exploitable Critical findings

Open `report.html` (or the findings table in the Web UI). Look at the **Exploitable** column. Findings marked **⚡ YES** are in the CISA Known Exploited Vulnerabilities catalog — they are not theoretical; attackers are actively using them in the wild today. **These are the ones to fix first, regardless of severity label.**

Then look at the **Critical** count. Even if none are marked exploitable yet, Critical means a remote code execution or privilege escalation is possible with no authentication. These need a fix plan before the image ships to production.

### The five columns to read (in the Web UI or HTML report)

| Column | What it means in business terms |
|--------|--------------------------------|
| **CVE / ID** | The official identifier for the vulnerability. Click it to open the NVD entry with full technical detail. |
| **Package** | The software component inside the image that has the flaw. If it says `runc`, the problem is the container runtime on the host machine, not the image itself. |
| **Fixed In** | The version you need to upgrade to in order to fix this. If blank, no fix exists yet — consider replacing the package or the base image. |
| **Severity** | How bad it is: **Critical** (drop everything), **High** (fix this sprint), **Medium** (fix this quarter), **Low** (track it). |
| **Exploitable** | ⚡ YES = confirmed exploited in the real world. No = not yet publicly exploited. — = unknown. |

### What to do with the findings

1. **Exploitable = YES, any severity** → patch immediately or pull the image from service.
2. **Critical, not yet exploitable** → fix before the next production deployment.
3. **High** → fix within the current sprint; include in the sprint scope if not already.
4. **Medium / Low** → schedule. Review quarterly; accept with a written justification if unfixable.
5. **Blank "Fixed In"** → no upstream fix yet. Options: replace the package, pin a patched base image, or apply a compensating control and document the acceptance.

### How to share this with the team

- The **CSV export** (Web UI export button or `--format csv`) opens in Excel/Sheets. Sort by Severity descending, filter Exploitable = YES for an action list.
- The **Markdown report** (`report.md`) can be pasted into Confluence, Notion, or a GitHub issue.
- The **SARIF report** (`report.sarif`) uploads to GitHub Security tab or Azure DevOps and shows findings inline with the code.

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
- **SBOM** — Software Bill of Materials. A list of every package in an image. Use `--sbom` to generate a CycloneDX JSON file for compliance and supply-chain tools (e.g. Dependency-Track).
- **OSV.dev enrichment** — When online, the scanner queries [OSV.dev](https://osv.dev/) (a Google-maintained database) to fill in missing CVE IDs for findings Trivy returned without one. Covers Go, Python, npm, and other ecosystems. Skipped with `--offline`.
- **Host runc advisory** — Use `--check-runtime` to check if the container runtime on your machine (runc) has known escape vulnerabilities. These are bugs that let an attacker break out of a container onto the host. Trivy cannot see these because runc is not inside the image.
- **Offline mode** — Running the scanner without the internet. You use a previously downloaded database of vulnerabilities (useful in locked-down or air-gapped environments).
- **Baseline** — Scanning many images in one run and getting a summary (findings count, duration per image) and optional dashboard. See [Baseline](baseline.md).

---

## I see an error. What do I do?

Go to [Troubleshooting](troubleshooting.md). There we list common errors, what they mean, and what to do step by step (e.g. “Trivy not found” → run the install-deps script or use the Docker image).

---

## Where do I find things?

| I want to… | Go here |
|------------|--------|
| Install dependencies (one script, runs in background) | [What do I need installed?](#what-do-i-need-installed) above; [Getting started](getting-started.md) |
| Add Go/Trivy to PATH | [Adding tools to your PATH](#adding-tools-to-your-path) above |
| Update Trivy DB (e.g. once a day) | [Updating the Trivy database](#updating-the-trivy-database-once-a-day) above |
| Scan from the browser (no CLI) | [Web UI — scan from the browser](#web-ui--scan-from-the-browser) above; run `go run ./cmd/server` |
| Read a report as an executive | [Reading a scan report as an executive](#reading-a-scan-report-as-an-executive) above |
| Run my first scan | [Getting started](getting-started.md) |
| Understand every command and option | [CLI reference](cli-reference.md) |
| Set default options in a file (severity, format, output dir) | Put `scanner.yaml` or `.scanner.yaml` in your project; see [CLI reference — Config file](cli-reference.md#config-file) |
| Scan a Dockerfile as well as the image | Use `--dockerfile path/to/Dockerfile`; see [CLI reference](cli-reference.md) |
| Add the scanner to my pipeline (Azure, GitHub, etc.) | [CI/CD primer](ci-cd-primer.md) |
| Run a baseline (many images) | [Baseline](baseline.md) |
| Use the scanner from VS Code, Cursor, or JetBrains; or from an AI assistant (MCP) | [IDE plugins and MCP server](ide-and-mcp.md) |
| See where image lists come from (registries, sites) | [Image sources](image-sources.md) |
| Own hardened image repo; local/private registry; microservices | [Hardened images and local registries](hardened-images-and-local-registries.md) |
| Clean up images after a baseline | [Baseline — After the run](baseline.md#after-the-run-results-and-cleanup); [Cleaning up](#cleaning-up-after-a-baseline) above |
| Run sanity checks before a PR | [Sanity checklist](sanity.md) |
| Fix an error | [Troubleshooting](troubleshooting.md) |
| Make the pipeline fail on Critical/High | Use `--fail-on-severity CRITICAL,HIGH`; see [CLI reference](cli-reference.md) |
| See how we compare to other scanners | [Comparison](COMPARISON.md) |
| Understand Exploitable, Why severity, CISA KEV | [Vulnerability reports](vulnerability-reports.md) |

---

## Who updates this?

The docs are kept in sync with the product. If something here doesn’t match what you see when you run the scanner, please report it or open a pull request.
