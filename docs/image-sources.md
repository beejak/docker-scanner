# Image sources — registries, sites, and repos

This document lists **every registry, website, and repository** we reference for container images used in baseline and scan tests. When adding or changing image lists, update this file and point list entries to these sources.

---

## Registries and URLs

| Registry / source | URL / pull prefix | Auth | Used in lists |
|-------------------|-------------------|------|----------------|
| **Docker Hub** | https://hub.docker.com/ — pull: `docker.io` or implicit (e.g. `alpine:latest`) | Anonymous pull rate-limited; `docker login` for more. | `images.txt`, `images-lesser-known.txt`, `images-5-registries.txt`, `images-obscure.txt` |
| **Docker Hub — official images tags** | e.g. https://hub.docker.com/_/alpine/tags , https://hub.docker.com/_/debian/tags | Same as above. | Older tags in `images.txt`, `images-lesser-known.txt`, `images-obscure.txt` |
| **Docker Library (source of truth)** | https://github.com/docker-library/official-images | N/A (definitions only; images live on Docker Hub). | Reference for what official tags exist. |
| **GitHub Container Registry (GHCR)** | https://github.com/orgs/ORG/packages — pull: `ghcr.io/org/repo:tag` | Public images often anonymous; private need PAT. | `images-other-registries.txt`, `images-5-registries.txt`, `images-obscure.txt` |
| **Chainguard Images** | https://images.chainguard.dev/ — pull: `cgr.dev/chainguard/NAME:tag` | Some images public; some (e.g. `alpine`) may be restricted. | `images-hardened.txt`, `images-other-registries.txt`, `images-5-registries.txt` |
| **Quay.io** | https://quay.io/ — pull: `quay.io/org/repo:tag` | Many public; some repos require login. | `images-other-registries.txt`, `images-5-registries.txt`, `images-obscure.txt` |
| **Red Hat UBI** | https://catalog.redhat.com/software/containers — pull: `registry.access.redhat.com/ubi8/...` | Public pull for UBI. | `images-hardened.txt`, `images-other-registries.txt`, `images-5-registries.txt` |
| **Google Container Registry (legacy)** | https://cloud.google.com/container-registry — pull: `gcr.io/...` | Many legacy images; newer Artifact Registry often needs auth. | `images-other-registries.txt` (commented) |
| **Amazon ECR Public** | https://gallery.ecr.aws/ — pull: `public.ecr.aws/...` | Anonymous pull for public repos. | `images-obscure.txt` |
| **Local / private registry** | Your registry URL (e.g. `myreg.local:5000`, `harbor.company.com`) — pull: `HOST/org/repo:tag` | Use `docker login <registry>` with credentials from devs/CI secrets. | Your own list (e.g. `images-local.txt`); see [Hardened images and local registries](hardened-images-and-local-registries.md). |

---

## Where to find older or obscure images

| Goal | Where to look |
|------|----------------|
| **Older official image tags** | Docker Hub Tags tab: e.g. [alpine/tags](https://hub.docker.com/_/alpine/tags), [debian/tags](https://hub.docker.com/_/debian/tags). Older versions (e.g. Alpine 3.6, Debian stretch) are still listed and pullable. |
| **Deprecated / unmaintained repos** | Docker Hub shows “not updated in over a year” on repos; archived repos are read-only but still pullable. |
| **GHCR public images** | Browse GitHub org/repo → Packages, or search GitHub for `docker.pkg.github.com` / `ghcr.io` in READMEs. No single directory; discover via projects (e.g. nginxinc, chainguard-images). |
| **Quay.io** | https://quay.io/ — search by organization (e.g. prometheus, coreos, openshift). |
| **ECR Public** | https://gallery.ecr.aws/ — search/filter by verified publishers, OS, architecture. |
| **Chainguard** | https://images.chainguard.dev/ — directory of Chainguard images; tag history via Chainguard docs/API. |

---

## Baseline image lists and their sources

| File | Primary source(s) | Notes |
|------|--------------------|--------|
| `tests/baseline/images.txt` | Docker Hub (library), Red Hat UBI, Chainguard (cgr.dev) | Main list; 100+ images. |
| `tests/baseline/images-hardened.txt` | cgr.dev, registry.access.redhat.com | Minimal/hardened only. |
| `tests/baseline/images-lesser-known.txt` | Docker Hub (older tags) | Older Alpine, Debian stretch, older Node/Python/Redis etc. |
| `tests/baseline/images-other-registries.txt` | ghcr.io, cgr.dev, quay.io, registry.access.redhat.com, gcr.io (optional) | Avoids Docker Hub rate limits. |
| `tests/baseline/images-5-registries.txt` | Docker Hub, ghcr.io, cgr.dev, quay.io, Red Hat | One image per registry for a quick multi-registry run. |
| `tests/baseline/images-workflow-test.txt` | Docker Hub (old+new), ghcr.io, quay.io, Red Hat, cgr.dev | Few old and new images for **workflow test**: use with `scripts/run-workflow-test.ps1` or `run-workflow-test.sh` to pull (optional) and scan each with config. |
| `tests/baseline/images-obscure.txt` | Docker Hub (old tags), GHCR, Quay, ECR Public | Older/obscure tags and repos for scanner coverage. |
| Your list (e.g. `images-local.txt`) | Local or private registry | Add refs after `docker login`; see [Hardened images and local registries](hardened-images-and-local-registries.md). |

---

## Adding new images

1. Identify the **registry and repo** (and optional tag) from the table above.
2. Add the image ref to the appropriate list in `tests/baseline/`.
3. If you introduce a **new registry or site**, add a row to the first table and a list row above, and note the URL and auth behavior here.

This keeps a single place to see where every image comes from and how to find more.

---

## Notes

- **Obscure list:** `images-obscure.txt` includes very old tags (e.g. Alpine 3.5, Debian jessie). Some may be removed by publishers over time; baseline will report FAIL for those. Replace or remove refs as needed.
- **Auth:** For any registry, if pull is denied or forbidden, use `docker login <registry>` (or CI secrets) where you have access.
