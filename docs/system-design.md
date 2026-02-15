# System design

Concise architecture for the Docker Container Scanner: components, data flow, interfaces, deployment, failure modes, and security.

## Components and boundaries

| Component | Ownership | Responsibility |
|-----------|-----------|----------------|
| **CLI** (`cmd/cli`) | Entrypoint | Parse flags/config, call scanner + enricher + report; write outputs. |
| **Scanner engine** (`pkg/scanner`) | Trivy wrapper | Invoke Trivy (or Grype) on image/Dockerfile; parse JSON into internal **finding model**. |
| **Remediation enricher** (`pkg/remediate`) | Enrichment | Take raw findings; add fixed version, upgrade text, CVE links (Trivy + OSV or rules); output enriched findings. |
| **Report generator** (`pkg/report`) | Output | Take enriched findings; produce SARIF 2.1, Markdown, HTML. Single code path for all formats. |
| **Server** (`cmd/server`) | Optional | Serve Web UI; expose `POST /scan` (image ref or tarball + options); run CLI/engine; return report (JSON/file). |
| **Web UI** (`web/`) | Frontend | Drop zone (ref or tarball), options form, progress, report view; client of server. |

- **Finding model**: Single schema (e.g. `pkg/scanner` or shared `pkg/model`) used by enricher and report. No duplicate definitions.
- **No CVE DB in this repo**: We use Trivy (or Grype) as the engine; we do not build or maintain a vulnerability database.

## Data flow

```
Image ref or tarball
    → Scanner engine (Trivy) → raw findings (JSON)
    → Remediation enricher   → enriched findings (in-memory / same model)
    → Report generator      → SARIF, Markdown, HTML
```

- Same flow for **CLI** and **server**: server runs the same scanner logic (CLI subprocess or shared packages); UI is a client of the server.
- **Image + Dockerfile**: When `--dockerfile` is set, the engine runs Trivy image (vulnerabilities) and Trivy config (misconfigurations on the Dockerfile directory); findings are merged into one list before enricher and report.
- **Offline**: Enricher uses only Trivy output + embedded rules; no OSV or other network calls. Trivy config uses `--skip-policy-update` when offline.
- **Baseline (optional)**: Second scan (baseline image) → diff (findings in target but not in baseline) → report/fail on delta.

## Key interfaces

- **CLI**: Flags and config file (e.g. `--image`, `--dockerfile`, `--severity`, `--offline`, `--baseline-image`, `--output-dir`, `--cache-dir`, `--format`). Env vars for registry auth (no secrets in config).
- **Server API**: `POST /scan` — body: image ref and/or tarball upload, options (JSON); response: report (JSON) and/or file download. Optional `GET /health`.
- **Finding model**: Go struct(s) for a single finding: CVE ID, package, current/fixed version, severity, title, description, remediation text, remediation links. Used by enricher and report.
- **Report formats**: SARIF 2.1 (for Azure/GitHub Security tab), Markdown, HTML. All generated from the same enriched finding list.

## Deployment topologies

1. **CLI-only**: Single binary in CI; no server. Pipeline runs `scanner scan --image ...` and publishes SARIF/artifacts.
2. **CLI + server + UI in one image**: `scanner serve` runs HTTP server and serves `web/`; same image can run `scanner scan` for CLI. One container for local or internal use.
3. **Separate UI image**: Optional `scanner-ui` image runs only server + frontend; calls scanner CLI in another container or on host (e.g. Docker socket).
4. **Air-gapped**: Offline bundle (image + Trivy DB snapshot); no server required; CLI with `--offline` and pre-populated cache.

Auth: Server can sit behind a reverse proxy (OAuth, SSO). CLI uses env vars or Docker config for registry auth; no secrets in logs or reports.

## Failure modes and limits

- **Timeouts**: Configurable timeouts for pull, scan, and enrichment; return clear error and non-zero exit code.
- **Large images**: Stream progress; optional memory caps; document resource requirements.
- **Concurrent scans**: Server can run one scan at a time (or a small queue) to avoid overload; document concurrency model.
- **Trivy/OSV unavailable**: Offline path (skip DB update, skip OSV); clear error message and link to troubleshooting.

## Security

- **No secrets in logs or reports**: Registry credentials via env or Docker config only; never log or write to report.
- **Server**: Validate image ref (format, length); limit tarball size; optional auth (e.g. API key or proxy).
- **CLI**: No plaintext secrets in config file; prefer env vars for sensitive data.

---

*Update this doc when adding server, UI, or new deployment options. Link from README and CONTRIBUTING.*
