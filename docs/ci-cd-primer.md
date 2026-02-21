# CI/CD integration primer (non‑prod pipelines)

This page is a **simple, step‑by‑step guide** for adding the Docker Container Scanner to a **non‑production** pipeline. It assumes you are not deeply technical but need to implement this yourself.

---

## What the scanner does in a pipeline

- **Runs after you build** a container image (or on a schedule).
- **Scans that image** for known vulnerabilities (CVEs).
- **Writes reports** (Markdown, CSV, SARIF, HTML) so you can see what was found and how to fix it.
- **Can fail the pipeline** if you find Critical or High severity issues (so you don’t ship bad images).

You run it **once per build** (or on a schedule) in a **non‑prod** pipeline so you catch problems before they reach production.

---

## When to run it

- **Best:** Right after you build the image in your pipeline (e.g. after the “Build image” step).
- **Alternative:** On a schedule (e.g. nightly) against a list of images you care about (using the baseline tool).

For most teams, “run after build” is enough for non‑prod.

---

## What you need before you start

1. **Docker** (or another container runtime) in the pipeline so the scanner can run.
2. **The scanner** available in the pipeline:
   - Either build the scanner image in the pipeline and run it, or
   - Use a pre‑built image from your registry (if you publish it there).
3. **No secrets in code.** Use your pipeline’s secret store for registry login (e.g. `docker login` with a token). See your pipeline’s docs for “store a secret” and “use it in a step.”

---

## How to run the scanner (one image)

After you build your app image (e.g. `myapp:latest` or `myreg.io/myapp:$(Build.BuildId)`):

1. **Log in to the registry** (if your image is in a private registry), using a secret from the pipeline — do **not** put passwords in the YAML.
2. **Run the scanner** against that image and write reports to a folder.
3. **Publish that folder** as a pipeline artifact so you can download the reports.
4. **(Optional)** **Fail the pipeline** if the scan finds Critical or High severity.

**Example (conceptual):**

```text
Build image  →  (optional) docker login with secret  →  Run scanner  →  Publish reports  →  (optional) Fail on severity
```

**CLI you’ll use (inside a “Run scanner” step):**

- Scan one image and write reports to a directory:
  - `scan --image <YOUR_IMAGE> --output-dir /reports --format sarif,markdown,html,csv`
- To **fail the pipeline** if there are Critical or High findings:
  - Add: `--fail-on-severity CRITICAL,HIGH`

Replace `<YOUR_IMAGE>` with the image you just built (e.g. `myapp:latest` or the full tag your pipeline uses). For scanning a **root filesystem** (e.g. on a host or in LXC), use `--fs <path>` or `--lxc <name>` instead of `--image`; see [CLI reference](cli-reference.md#scan).

**Config file (optional):** You can put a **`scanner.yaml`** (or `.scanner.yaml`) in your repo with default `severity`, `format`, `output-dir`, or `fail-on-severity`. The pipeline step then only needs `--image <ref>`; the rest come from the config. See [CLI reference — Config file](cli-reference.md#config-file).

---

## Where reports go

- **In the pipeline:** You choose a directory (e.g. `/reports` or `$(Build.ArtifactStagingDirectory)`). The scanner writes files there: `report.md`, `report.sarif`, `report.html`, `report.csv`, etc.
- **After the run:** Add a step to **publish that directory as a pipeline artifact** (e.g. “Publish Pipeline Artifact” or “Upload artifact”). Then anyone can download the reports from the pipeline run.
- **SARIF:** If you upload `report.sarif` to GitHub or Azure DevOps, they can show findings in the Security tab. See your pipeline’s docs for “upload SARIF.”

---

## Failing the pipeline on severity

- Use **`--fail-on-severity CRITICAL,HIGH`** (or whatever severities you want). If the scanner finds any finding at that level, it exits with a non‑zero code and the pipeline step fails.
- For **non‑prod**, failing on **CRITICAL** and **HIGH** is a common choice. You can start with **CRITICAL** only and then add **HIGH** once you’re used to it.

---

## Baseline run (many images) in CI

If you want to scan **many images** (e.g. a list of base images or “lesser‑known” images) on a **schedule** (e.g. nightly):

1. Put the image list in a file (e.g. `tests/baseline/images.txt` or `tests/baseline/images-lesser-known.txt`).
2. In the pipeline, run the **baseline** command with env vars, for example:
   - `BASELINE_IMAGES=tests/baseline/images-lesser-known.txt`
   - `BASELINE_OUT=test-results`
   - `BASELINE_WORKERS=1`
   - `BASELINE_LIMIT=10`
   - `BASELINE_RANDOM=1`
   - `BASELINE_DELAY_SEC=10`
   - `BASELINE_PULL_FIRST=1`
3. Publish the **output folder** (`test-results/` or whatever you set) as an artifact. It will contain CSV, Markdown, and a dashboard HTML.

See [Baseline test](baseline.md) for all options. No credentials in code — use `docker login` (with a pipeline secret) if you pull from a private registry.

---

## Example: GitHub Actions (non‑prod)

1. In your repo, add or edit a workflow under `.github/workflows/` (e.g. `scan.yml`).
2. Trigger it on push (or pull_request) to a non‑prod branch.
3. Steps (conceptual):
   - Checkout code.
   - Build your app image (e.g. `docker build -t myapp:latest .`).
   - (Optional) Log in to a registry using a secret (e.g. `GHCR` or Docker Hub token).
   - Build or pull the scanner image, then run:
     - `docker run --rm -v $PWD/reports:/reports scanner:latest scan --image myapp:latest --output-dir /reports --format sarif,markdown --fail-on-severity CRITICAL,HIGH`
   - Upload the SARIF file (if you use GitHub Code Scanning): `github/codeql-action/upload-sarif`.
   - Upload the `reports/` folder as an artifact so you can download the Markdown/HTML/CSV.

Templates are in `ci/github/workflow.example.yml`; adapt the image name and the `--fail-on-severity` to your policy.

---

## Example: Azure DevOps (non‑prod)

1. Create or edit a pipeline (YAML) that builds your image.
2. Add steps after the build:
   - (Optional) Docker login using a pipeline variable (secret).
   - Run the scanner container, mounting a folder for reports; use the same `scan --image ... --output-dir ... --format sarif,markdown --fail-on-severity CRITICAL,HIGH` idea.
   - Publish SARIF with `PublishSecurityAnalysisResults@1`.
   - Publish the reports folder with `PublishPipelineArtifact@1`.

Templates are in `ci/azure/pipeline.example.yml`; replace the image name and options as above.

---

## Checklist (layman summary)

| Step | What to do |
|------|------------|
| 1 | Run the scanner **after** you build the image (or on a schedule for baseline). |
| 2 | Use **one** “Run scanner” step: `scan --image <IMAGE> --output-dir <DIR> --format sarif,markdown,html,csv`. |
| 3 | Add **`--fail-on-severity CRITICAL,HIGH`** if you want the pipeline to fail when those are found. |
| 4 | Publish the **reports directory** as an artifact so you can open the Markdown/HTML/CSV. |
| 5 | (Optional) Upload **SARIF** so your platform (GitHub/Azure) shows findings in the Security tab. |
| 6 | Keep **secrets** (registry passwords, tokens) in the pipeline’s secret store; never put them in the YAML. |

Once this is in place, every non‑prod build (or scheduled run) will produce documented results; you can then decide when to clean up old images and artifacts (e.g. delete pulled images after reviewing; see [Baseline – After the run](baseline.md#after-the-run-results-and-cleanup)).
