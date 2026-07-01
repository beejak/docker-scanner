# AWS CodeBuild integration

Add the Docker Container Scanner to your CodeBuild project so every build is scanned, reports are archived to S3, and CRITICAL/HIGH findings fail the build.

## Prerequisites

### CodeBuild project settings

- **Privileged mode** must be enabled. Docker-in-Docker requires it.
  Go to **CodeBuild → your project → Edit → Environment** and check
  **Enable this flag if you want to build Docker images or want your builds to get elevated privileges**.
- **Compute type**: at least `BUILD_GENERAL1_SMALL` (2 vCPU / 3 GB RAM). Use
  `BUILD_GENERAL1_MEDIUM` for larger images or faster Go builds.
- **Environment image**: use a managed image that includes Docker, e.g.
  `aws/codebuild/standard:7.0` (Amazon Linux 2023, Docker pre-installed).

### IAM role

The service role attached to your CodeBuild project needs the following ECR permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "ecr:CompleteLayerUpload",
    "ecr:InitiateLayerUpload",
    "ecr:PutImage",
    "ecr:UploadLayerPart"
  ],
  "Resource": "*"
}
```

`ecr:GetAuthorizationToken` must use `Resource: "*"` (it is a global API call).
Scope the remaining actions to your specific ECR repository ARN in production:
`arn:aws:ecr:<region>:<account-id>:repository/<repo-name>`.

### ECR repository

Create the target ECR repository before the first build:

```bash
aws ecr create-repository \
  --repository-name myapp \
  --region us-east-1
```

## Environment variables

Set these in **CodeBuild project → Edit → Environment → Environment variables**.

| Variable | Where it comes from | Example value |
|---|---|---|
| `AWS_ACCOUNT_ID` | **User-defined** — set in project settings | `123456789012` |
| `ECR_REPO_NAME` | **User-defined** — set in project settings (default: `myapp`) | `myapp` |
| `AWS_DEFAULT_REGION` | **CodeBuild built-in** — injected automatically | `us-east-1` |
| `CODEBUILD_RESOLVED_SOURCE_VERSION` | **CodeBuild built-in** — full Git commit SHA | `a1b2c3d4...` |

`AWS_DEFAULT_REGION` and `CODEBUILD_RESOLVED_SOURCE_VERSION` do **not** need to
be added manually; CodeBuild sets them for every build.

## How Docker becomes available

CodeBuild's managed images ship with the Docker daemon. It starts automatically
when **privileged mode** is enabled on the project. No additional installation
steps are needed — the `install` phase in the buildspec simply verifies it is
running with `docker version`.

If you see `Cannot connect to the Docker daemon` errors, the most common cause
is that privileged mode is disabled on the project. Re-enable it under
**Edit → Environment → Privileged**.

## Buildspec location

Place `ci/aws-codebuild/buildspec.yml` (provided in this repo) at the root of
your source, or point CodeBuild at it explicitly:

**Project settings → Buildspec → Use a buildspec file → Buildspec name:**
```
ci/aws-codebuild/buildspec.yml
```

## Passing the ECR registry URL

The full ECR registry URL is constructed inside the buildspec from the two
environment variables:

```
$AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com
```

You do **not** need to hard-code the URL. Adjust `ECR_REPO_NAME` to match your
ECR repository name if it differs from `myapp`.

## Viewing reports as CodeBuild artifacts

Reports are written to `reports/` and published to S3 automatically when
**Artifacts** are configured on the project.

1. Go to **CodeBuild → your project → Edit → Artifacts**.
2. Set **Type** to `Amazon S3`.
3. Choose or create an S3 bucket (e.g. `my-codebuild-artifacts`).
4. Set **Name** (optional path prefix, e.g. `scan-reports`).
5. Save the project.

After a build, open the **Build details** page and click **Artifacts** to
download or browse the `reports/` directory directly from S3.

Formats produced by the scan: `report.sarif`, `report.md`, `report.html`,
`report.csv`, and an SBOM file. All are included in the artifact.

## Failing the build on CRITICAL or HIGH findings

The `--fail-on-severity CRITICAL,HIGH` flag causes the scanner to exit with
code `1` when any vulnerability at those severities is found. CodeBuild treats
a non-zero exit code from any `commands` entry as a build failure, so no
additional configuration is needed.

To change the gate:
- Use `--fail-on-severity HIGH` to ignore CRITICAL-only (unusual).
- Remove the flag entirely to always pass, treating scan results as advisory.
- See [CLI reference](../cli-reference.md) for all available flags.

## Sending SARIF to AWS Security Hub

AWS Security Hub can ingest SARIF findings via the
`batch-import-findings` API. After the scan completes, add this one-liner to
the `post_build` commands (after the scanner step):

```bash
# Convert SARIF findings and send to AWS Security Hub.
# Requires Security Hub to be enabled in your account and the CodeBuild role
# to have securityhub:BatchImportFindings permission.
aws securityhub batch-import-findings \
  --findings "$(
    python3 - <<'EOF'
import json, sys

with open('reports/report.sarif') as f:
    sarif = json.load(f)

findings = []
for run in sarif.get('runs', []):
    tool = run.get('tool', {}).get('driver', {}).get('name', 'docker-scanner')
    for result in run.get('results', []):
        msg = result.get('message', {}).get('text', '')
        level = result.get('level', 'warning')
        severity = {'error': 'CRITICAL', 'warning': 'HIGH', 'note': 'INFORMATIONAL'}.get(level, 'MEDIUM')
        for loc in result.get('locations', [{}]):
            uri = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
            findings.append({
                'SchemaVersion': '2018-10-08',
                'Id': result.get('ruleId', 'unknown') + '-' + uri,
                'ProductArn': f"arn:aws:securityhub:$AWS_DEFAULT_REGION:$AWS_ACCOUNT_ID:product/$AWS_ACCOUNT_ID/default",
                'GeneratorId': tool,
                'AwsAccountId': '$AWS_ACCOUNT_ID',
                'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                'CreatedAt': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
                'UpdatedAt': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
                'Severity': {'Label': severity},
                'Title': msg[:256],
                'Description': msg[:1024],
                'Resources': [{'Type': 'Container', 'Id': '$IMAGE_URI'}],
            })
print(json.dumps(findings[:100]))  # batch-import-findings max is 100 per call
EOF
  )"
```

For production use, consider a dedicated Lambda or pipeline stage that pages
through all results in batches of 100.

## See also

- [CLI reference](../cli-reference.md) — all scanner flags (`--severity`,
  `--offline`, `--baseline-image`, `--sbom`, `--check-runtime`, etc.)
- [ci/aws-codebuild/buildspec.yml](../../ci/aws-codebuild/buildspec.yml) — the
  full, annotated buildspec
- [COMPARISON.md](../COMPARISON.md) — how AWS CodeBuild compares with other
  CI integrations in this repo
