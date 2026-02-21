# Hardened images and local/private registries

This page explains what **hardened images** are, how to **create your own repo** of hardened images for local use, how **microservices** fit into scanning, and how to **pull and scan images from local or private registries** when devs give you access.

---

## What is a hardened image?

A **hardened** container image is built to reduce attack surface and stay closer to security best practices. Typical traits:

| Trait | What it means |
|------|----------------|
| **Minimal base** | Small OS (Alpine, distroless, Wolfi) or minimal variants (e.g. `-slim`, `-alpine`) so there are fewer packages to patch. |
| **Distroless / no shell** | No shell or package manager in the image; harder to exploit interactively. |
| **Non-root** | Runs as non-root user; fewer privileges. |
| **Pinned / signed** | Tags or digests and optional signing so you get a known, audited build. |
| **Regular updates** | Maintained with security fixes and rebased on updated bases. |

Examples we use in baseline: **Chainguard** (cgr.dev), **Red Hat UBI** (ubi-minimal, ubi-micro), and **Docker official** slim/alpine variants. You can treat any image that meets your own “hardened” criteria as part of your repo.

---

## Your own repo of hardened images (for local use)

You don’t need a special “repo type”—you maintain a **curated list** of image refs that your team considers hardened. Optionally those images live in **your own registry** (local or private).

### Option A: List only (no separate registry)

1. Create a text file (e.g. `tests/baseline/images-hardened-myteam.txt`) with one image ref per line.
2. Add images you consider hardened: your own builds (e.g. `myreg.io/myteam/base-node:hardened`), plus any third-party ones (Chainguard, UBI, etc.).
3. Run baseline with that list:
   - `BASELINE_IMAGES=tests/baseline/images-hardened-myteam.txt go run ./cmd/baseline`
   - Or use it as the “hardened” list: `BASELINE_IMAGES_HARDENED=tests/baseline/images-hardened-myteam.txt` and set `BASELINE_HARDENED_LIMIT` as needed.

No extra tooling: same scanner, same baseline, different list.

### Option B: Local or private registry

1. **Run a registry** (e.g. Docker Registry, Harbor, Quay, or your cloud registry) and push your hardened images there.
2. **Create a list file** with refs pointing at that registry, e.g.:
   - `myregistry.local:5000/myteam/base-alpine:1.0`
   - `harbor.mycompany.com/secure/node:18-hardened`
3. **Log in** so the scanner (and baseline) can pull: `docker login myregistry.local:5000` (or your registry URL). Use a robot account or token that only has pull access.
4. Use that file as in Option A: `BASELINE_IMAGES=<path-to-list>` or `BASELINE_IMAGES_HARDENED=<path-to-list>`.

The scanner doesn’t care whether the ref is Docker Hub or a local registry—it’s just an image ref. Pull is done by Docker/containerd (after you log in).

### What to put in “your” hardened repo

- **Internally built** images that follow your hardening standard (minimal base, non-root, etc.).
- **Approved third-party** images (e.g. Chainguard, UBI) that you re-tag or mirror into your registry for consistency and availability.
- **One image ref per line** in the list; use `#` for comments. See [Image sources](image-sources.md) and [Baseline](baseline.md).

---

## Microservices and scanning

The scanner works at **image** level: one scan per image, and it reports OS/package vulnerabilities for the **whole image filesystem**. It does not know about “microservice A” vs “microservice B” inside the same image.

- **One image per microservice (recommended):** Each microservice has its own image (e.g. `api:v1`, `worker:v1`). Put **all** those image refs in your baseline list (or in your hardened list if they’re built to your hardened standard). The scanner runs **one scan per image**; the report and dashboard are per image. So you effectively “scan those microservices alongside the Docker images” by scanning each microservice’s image.
- **Multiple microservices in one image:** If you run several processes in a single image, we still only scan that image once. You get one set of findings for the whole image; you can’t attribute a CVE to a specific process. For per-microservice visibility, use **one image per microservice** and list them all.

So: **yes, you can scan microservices “alongside” Docker images** by treating each microservice as its own image and adding those refs to the list. No code change required—just list all microservice images (and optional hardened base images) in your baseline or hardened list.

---

## Pulling images from local or private repos (when devs give access)

The scanner **already supports** any registry: if Docker can pull the image, we can scan it. “Local repo” = a registry (local or private) that you pull from using normal image refs.

### Steps

1. **Get access** from devs: registry URL, and either a pull-only token/robot account or credentials (username + password or token).
2. **Log in** from the machine (or CI job) that runs the scanner:
   ```bash
   docker login <REGISTRY_URL>
   ```
   Example: `docker login myregistry.company.com` or `docker login harbor.myteam.io`. Use the credentials they provided.
3. **Add image refs** to a list file. Refs look like:
   - `myregistry.company.com/myteam/api:v1`
   - `harbor.myteam.io/project/frontend:latest`
   - `localhost:5000/internal/base:hardened`
4. **Run the scanner or baseline** with that list:
   - Single scan: `scanner scan --image myregistry.company.com/myteam/api:v1 --output-dir ./reports`
   - Baseline: `BASELINE_IMAGES=path/to/your-list.txt go run ./cmd/baseline`

No scanner code change is required: we don’t “add” local repos as a special feature—you add the **image refs** to a list and ensure **docker login** has been done so pulls succeed.

### Example: dedicated list for local/private images

Create a file, e.g. `tests/baseline/images-local.txt` (or `images-myteam-private.txt`), and put in it only refs that point at your local or private registry. Use it like any other list:

```bash
# After: docker login myregistry.company.com
export BASELINE_IMAGES=tests/baseline/images-local.txt
go run ./cmd/baseline
```

In CI, store the registry credentials in a secret and run `docker login` in the job before the scan step (see [CI/CD primer](ci-cd-primer.md)). Never put passwords or tokens in the image list or in code.

### Documenting the source

When you introduce a new registry (e.g. your company’s Harbor or local registry), add it to [Image sources](image-sources.md): registry URL, auth note, and which list file uses it. That keeps one place where “where do these images come from?” is answered.

---

## Summary

| Question | Answer |
|----------|--------|
| Can I have my own repo of hardened images? | Yes. Create a list file of image refs you consider hardened; optionally host those images in your own registry. Use that file as `BASELINE_IMAGES` or `BASELINE_IMAGES_HARDENED`. |
| What constitutes a hardened image? | Minimal base, fewer packages, non-root, distroless/signed where possible, regularly updated. You define your own bar and which refs go in the list. |
| Can we scan microservices alongside Docker images? | Yes, by scanning **one image per microservice**. Add all microservice image refs to the baseline list; the report is per image (per microservice). |
| Can we pull from local repos if devs give access? | Yes. Use `docker login <registry>`, then add the registry’s image refs to a list and run the scanner/baseline as usual. Document the registry in [Image sources](image-sources.md). |
