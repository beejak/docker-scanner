# Baseline test (100+ images)

The baseline run scans a list of **100+ images** (Alpine, Debian, Ubuntu, Busybox, Node, Python, Redis, Nginx, Postgres, etc.) in parallel, records **findings count** and **duration per image**, and writes a report so you can see where the product stands and track regressions. For scanning a **single root filesystem** (e.g. an LXC container), use the CLI with `--fs <path>` or `--lxc <name>`; see [CLI reference — scan](cli-reference.md#scan).

## Run baseline

From repo root with **Trivy and Go in PATH**. If you don’t have them yet, run the [install-deps script](getting-started.md#install-dependencies-from-source) for your OS first (`./scripts/install-deps.sh` or `.\scripts\install-deps.ps1`).

```bash
go run ./cmd/baseline
```

**Options (env):**

- `BASELINE_IMAGES` – path to image list (default: `tests/baseline/images.txt`)
- `BASELINE_OUT` – output directory (default: `test-results`)
- `BASELINE_WORKERS` – number of parallel scans (default: 5). Use `1` if you see Trivy cache lock errors.
- `BASELINE_LIMIT` – scan only the first N images (e.g. `10`). Use with `BASELINE_RANDOM=1` for a random subset.
- `BASELINE_RANDOM` – if set (e.g. `1`), shuffle the image list before applying `BASELINE_LIMIT`.
- `BASELINE_DELAY_SEC` – delay in seconds between each scan (e.g. `10`). Use 10s between pulls to respect Docker Hub rate limits.
- `BASELINE_PULL_FIRST` – if set (e.g. `1`), run `docker pull <image>` before each scan so the image is local and Trivy doesn’t hit the registry during scan. Use with `BASELINE_DELAY_SEC=10` so the delay runs *between* each (pull+scan), respecting Docker Hub rate limits.
- `BASELINE_IMAGES_HARDENED` – path to a second image list (hardened/minimal images). If set, those images are appended after the main list (e.g. 10 random + 5 hardened).
- `BASELINE_HARDENED_LIMIT` – how many images to take from the hardened list (default: 5). They are shuffled and the first N are appended.
- **Rate-limit friendly run:** `BASELINE_WORKERS=1 BASELINE_LIMIT=10 BASELINE_RANDOM=1 BASELINE_DELAY_SEC=10 BASELINE_PULL_FIRST=1` – pull then scan 10 random images (including hardened), one at a time, with 10s between each (pull+scan).

**Output:**

- `test-results/baseline-YYYYMMDD-HHMMSS.csv` – **summary**: one row per image (Image, Findings count, Duration_sec, Status, Error)
- `test-results/baseline-YYYYMMDD-HHMMSS.md` – same summary as a table with **Duration (s)** and summary (OK/FAIL counts, total time)
- `test-results/baseline-YYYYMMDD-HHMMSS-findings.csv` – **full findings**: one row per finding, with columns **Image**, CVE, **Title**, **Description**, Package, CurrentVersion, FixedVersion, Severity, **Exploitable**, **WhySeverity**, **ExploitInfo**, Path/Location, Remediation, RemediationLinks (same format as the single-image scan report, plus Image)
- `test-results/baseline-YYYYMMDD-HHMMSS-findings.md` – same findings as a Markdown table (Image, CVE, Title, Package, Severity, Exploitable, Why severity, Exploit info, Remediation)
- `test-results/baseline-YYYYMMDD-HHMMSS-dashboard.html` – **dashboard with graphs**: findings per image (image name/path), severity distribution, Exploitable (CISA KEV), scan duration per image. Open in a browser; no need to read the report to see trends.

**Scan order:** When `BASELINE_PULL_FIRST=1`, each image is **pulled then scanned immediately** (pull → scan → delay → next image). The **dashboard is written once at the end** after all scans finish; it is not updated live during the run. If the dashboard doesn’t show charts, open the browser developer console (F12) and check for blocked scripts (e.g. Chart.js from CDN); try opening the HTML from a local path or serve it with a simple HTTP server.

**Running without PATH:** If Go and Trivy are in your PATH, run `go run ./cmd/baseline` from repo root. Otherwise use `scripts\run-baseline.bat`, which sets PATH from common locations (edit TRIVY_DIR/GO_DIR if yours differ). Use `BASELINE_WORKERS=1` to avoid Trivy cache lock; the batch file sets it by default.

Scans run in parallel (default 5 workers). Each worker uses its own Trivy cache dir (`<BASELINE_OUT>/trivy-cache-baseline/w0` … `w4`) to avoid "cache may be in use by another process" errors. Each scan is timed; the report includes a **Duration (s)** column so you can see how long each image took. Findings are enriched with **Exploitable** (CISA KEV), **Why severity**, and **Exploit info** when you run the normal CLI scan; the baseline run aggregates counts and timing so you can spot gaps (e.g. images with many Critical/exploitable findings or slow scans). See [Vulnerability reports](vulnerability-reports.md).

## Image lists

- **`tests/baseline/images.txt`** – default: 100+ well-known official images from **Docker Hub** (Alpine, Debian, Ubuntu, Busybox, Node, Python, Redis, Nginx, Postgres, etc.) plus a hardened section. One image per line; `#` for comments.
- **`tests/baseline/images-hardened.txt`** – optional: hardened/minimal images (Chainguard, Red Hat UBI). Use with `BASELINE_IMAGES_HARDENED` and `BASELINE_HARDENED_LIMIT`.
- **`tests/baseline/images-lesser-known.txt`** – optional: lower-profile images (older tags, fewer pulls) from Docker Hub. Use for variety: set `BASELINE_IMAGES=tests/baseline/images-lesser-known.txt` (optionally with `BASELINE_LIMIT` and `BASELINE_RANDOM=1`).
- **`tests/baseline/images-other-registries.txt`** – optional: images from **other registries** (GitHub Container Registry, Quay.io, Chainguard, Red Hat). Use to avoid Docker Hub rate limits or to test multi-registry. Set `BASELINE_IMAGES=tests/baseline/images-other-registries.txt` (optionally with `BASELINE_LIMIT`). See [Other registries](#other-registries) below.
- **`tests/baseline/images-obscure.txt`** – optional: **older / obscure** tags and repos (Docker Hub old tags, GHCR, Quay, ECR Public, Red Hat). Use to test scanner on legacy and low-profile images. Set `BASELINE_IMAGES=tests/baseline/images-obscure.txt` (optionally with `BASELINE_LIMIT`, `BASELINE_RANDOM=1`). Some tags may no longer be available.
- **`tests/baseline/images-workflow-test.txt`** – **workflow test**: a few old and new images from different registries (Docker Hub, GHCR, Quay, Red Hat, Chainguard) for even distribution. Use with **`scripts/run-workflow-test.ps1`** (Windows) or **`scripts/run-workflow-test.sh`** (Linux/macOS) to pull (optional) and scan each image with config; reports go to `reports/` as `wf-<image>.md` / `.html`. See [Workflow test (pull + scan with config)](#workflow-test-pull--scan-with-config) below.

**Where images come from:** All registries, sites, and repos are documented in [Image sources](image-sources.md). When adding or changing image lists, update that file and reference it in list comments.

Use `BASELINE_RANDOM=1` and `BASELINE_LIMIT=10` to pick 10 random images from the chosen list (or from main + hardened when `BASELINE_IMAGES_HARDENED` is set).

## Other registries

Using images from registries other than Docker Hub can help with **rate limits** (Docker Hub throttles anonymous pulls) and **variety** (different vendors, minimal images, OSS projects).

| Registry | Examples | Auth / notes |
|----------|----------|--------------|
| **GitHub Container Registry (ghcr.io)** | `ghcr.io/nginxinc/nginx-unprivileged:alpine`, `ghcr.io/chainguard-images/alpine:latest` | Public images often pullable without auth; good for CI. |
| **Chainguard (cgr.dev)** | `cgr.dev/chainguard/alpine:latest`, `cgr.dev/chainguard/nginx:latest` | Minimal/distroless; public. |
| **Quay.io** | `quay.io/prometheus/prometheus:latest`, `quay.io/coreos/etcd:latest` | Red Hat / community; many OSS projects; some repos require auth. |
| **Red Hat (registry.access.redhat.com)** | `registry.access.redhat.com/ubi8/ubi-minimal:latest` | UBI images; public for pull. |
| **Google (gcr.io)** | Legacy public images; newer Artifact Registry often requires auth. | Use `docker login` or service account if needed. |

Use the list **`tests/baseline/images-other-registries.txt`** to run a baseline against a mix of these. For private images, run `docker login <registry>` (or set up CI secrets) before pulling.

## Workflow test (pull + scan with config)

To **pull a few old and new images from different repos** and **test the full workflow** (config file + scan → enrich → report):

1. From repo root, run:
   - **Windows:** `.\scripts\run-workflow-test.ps1` (or `-PullFirst` to pull each image before scanning)
   - **Linux/macOS:** `./scripts/run-workflow-test.sh` (or `--pull-first`)
2. The script uses **`tests/baseline/images-workflow-test.txt`** (about 10 images: Alpine/Debian/Nginx old and new from Docker Hub, plus one each from GHCR, Quay, Red Hat, Chainguard). It creates **`scanner.yaml`** from `scanner.yaml.example` if missing, builds the scanner if needed, then runs **`scanner scan --image <ref>`** for each image. Reports are written to **`reports/`** with names like **`wf-alpine-3.10.md`**, **`wf-alpine-latest.html`**, etc.
3. **Trivy** must be in PATH. Optional: use **`-PullFirst`** / **`--pull-first`** so images are pulled from the registries first (tests pull from Docker Hub, ghcr.io, quay.io, Red Hat, cgr.dev).

This exercises config-loaded defaults, multi-registry pull (if used), and the scan → enrich → report path on a small, evenly distributed set.

## Testing multiple microservices / one image per service

If you have **different microservices** running in your environment, plan testing by **image** (one scan per image):

- **One image per microservice (recommended):** Each microservice has its own container image. List all images in `tests/baseline/images.txt` (or a custom list). The baseline scans each image and reports findings per **image name/path**. The dashboard and findings CSV use that image name/path in every row and chart label, so you can see which service (image) has the most findings or longest scan.
- **Multiple services in one container:** If you run several microservices inside a single container (not recommended), the scanner still runs **one scan per image** and reports all OS/package vulnerabilities in that image. You get one row per finding with the same image name; you cannot attribute a CVE to a specific process inside the container. For per-service granularity, use **one image per microservice** and scan each image.

So: **treat each image as one unit**. Add every image you care about (e.g. `myreg.io/api:v1`, `myreg.io/worker:v1`) to the baseline list; the dashboard and reports will show results by image name/path.

## After the run: results and cleanup

**Where results are documented:** All outputs from a baseline run are in the folder you set with `BASELINE_OUT` (default: `test-results/`). The run creates a timestamped set: `baseline-YYYYMMDD-HHMMSS.csv`, `.md`, `-findings.csv`, `-findings.md`, and `-dashboard.html`. What was tested is the image list you used (`BASELINE_IMAGES`, and if set, `BASELINE_IMAGES_HARDENED`); the summary CSV/MD lists each image with its findings count, duration, and status (OK/FAIL). The findings CSV/MD and dashboard show per-finding and per-image details.

**When you're done reviewing:** To free disk space, delete the images that were pulled. Options:

- **By run:** `.\scripts\prune-baseline-run.ps1` (uses latest baseline CSV in `test-results/`) or `.\scripts\prune-baseline-run.ps1 -Csv test-results\baseline-YYYYMMDD-HHMMSS.csv`.
- **By time:** `.\scripts\prune-images-last-hour.ps1` (last 1 hour) or `.\scripts\prune-images-last-hour.ps1 -Hours 6` (e.g. last 6 hours; use `-Hours N` for any N).
- **Manual:** `docker image prune -a` or `docker rmi <image> ...`.

Run scripts from repo root. We recommend doing this after you've saved or published any reports you need.

## Using the baseline

- **Before/after changes:** Run baseline, save the CSV/MD. After improving the scanner or Trivy version, run again and compare findings and duration.
- **CI:** Add a job that runs `go run ./cmd/baseline` and publishes the report artifact. See [CI/CD primer](ci-cd-primer.md) for a step-by-step guide.
- **PDF:** For a printable report, open the generated `.md` in a viewer that exports to PDF, or use the HTML report and browser “Print to PDF”.

## Report formats (CLI)

- **CSV** – `--format csv` (or add to `--format sarif,markdown,html,csv`) for spreadsheets.
- **PDF** – The scanner does not generate PDF directly. Use “Print to PDF” in the browser on `report.html`, or convert the Markdown report with an external tool.
