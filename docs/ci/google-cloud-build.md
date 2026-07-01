# Google Cloud Build integration

Add the Docker Container Scanner to your Cloud Build pipeline so every push is scanned and reports are stored in GCS.

## Prerequisites

Before using the config at [`ci/google-cloud-build/cloudbuild.yaml`](../../ci/google-cloud-build/cloudbuild.yaml), make sure the following are in place.

### 1. Enable the Cloud Build API

```bash
gcloud services enable cloudbuild.googleapis.com
```

### 2. Create an Artifact Registry repository

```bash
gcloud artifacts repositories create my-app-images \
  --repository-format docker \
  --location us-central1 \
  --description "Application images"
```

### 3. Create a GCS bucket for scan reports

```bash
gcloud storage buckets create gs://${PROJECT_ID}-scan-reports \
  --location us-central1 \
  --uniform-bucket-level-access
```

---

## Substitution variables

Cloud Build supports two kinds of substitution variables.

### Built-in variables (injected automatically)

| Variable | Value |
|---|---|
| `$PROJECT_ID` | Your GCP project ID |
| `$SHORT_SHA` | First 7 characters of the commit SHA |
| `$BRANCH_NAME` | Git branch that triggered the build |
| `$REPO_NAME` | Cloud Source Repository or connected repo name |

These are always available and do not need to be declared.

### User-defined variables (`_*`)

User-defined substitutions must start with an underscore. They are declared in the `substitutions` block of `cloudbuild.yaml` with default values, and can be overridden in a Cloud Build trigger or on the command line.

```yaml
substitutions:
  _AR_REGION: us-central1
  _AR_REPO: my-app-images
  _APP_IMAGE: my-app
```

Override when running manually:

```bash
gcloud builds submit \
  --config ci/google-cloud-build/cloudbuild.yaml \
  --substitutions _AR_REGION=europe-west1,_AR_REPO=my-app-images,_APP_IMAGE=my-app .
```

Override in a trigger (Cloud Console → Cloud Build → Triggers → Edit → Substitution variables).

---

## Grant the Cloud Build service account the required roles

The Cloud Build service account is `[PROJECT_NUMBER]@cloudbuild.gserviceaccount.com`.

Find your project number:

```bash
gcloud projects describe $PROJECT_ID --format="value(projectNumber)"
```

### Artifact Registry Writer (to push images)

```bash
gcloud artifacts repositories add-iam-policy-binding my-app-images \
  --location us-central1 \
  --member "serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role roles/artifactregistry.writer
```

### Storage Object Creator (to upload scan reports)

```bash
gcloud storage buckets add-iam-policy-binding gs://${PROJECT_ID}-scan-reports \
  --member "serviceAccount:${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com" \
  --role roles/storage.objectCreator
```

---

## Create a Cloud Build trigger

### Via the CLI

```bash
gcloud builds triggers create github \
  --name container-security-scan \
  --repo-name YOUR_REPO \
  --repo-owner YOUR_GITHUB_ORG_OR_USER \
  --branch-pattern "^main$" \
  --build-config ci/google-cloud-build/cloudbuild.yaml \
  --substitutions _AR_REGION=us-central1,_AR_REPO=my-app-images,_APP_IMAGE=my-app
```

### Via the Cloud Console

1. Go to **Cloud Build → Triggers → Create trigger**.
2. Connect your source repository.
3. Set the build configuration to **Cloud Build configuration file** and point it to `ci/google-cloud-build/cloudbuild.yaml`.
4. Add your user-defined substitution variables under **Substitution variables**.

---

## View build logs and artifacts

- **Build logs**: Cloud Console → **Cloud Build → History** → click a build → **Build log** tab.
- **Build artifacts** (SARIF, Markdown, HTML reports): Cloud Console → **Cloud Storage → Buckets** → `${PROJECT_ID}-scan-reports` → navigate to the `$SHORT_SHA/` prefix.

Or via the CLI:

```bash
gcloud storage ls gs://${PROJECT_ID}-scan-reports/${SHORT_SHA}/
gcloud storage cp gs://${PROJECT_ID}-scan-reports/${SHORT_SHA}/report.sarif .
```

---

## SARIF reports and Security Command Center

Cloud Build does not have a native SARIF viewer. The `report.sarif` file is stored as a GCS object (see above). You have two options for making the findings visible:

### Option 1: Download and view locally

Copy the file from GCS and open it in a SARIF-aware editor (VS Code with the SARIF Viewer extension, for example).

```bash
gcloud storage cp gs://${PROJECT_ID}-scan-reports/${SHORT_SHA}/report.sarif report.sarif
```

### Option 2: Import to Security Command Center

If your project or organisation has Security Command Center (SCC) Standard or Premium enabled, you can import SARIF findings using the SCC API or the `gcloud scc` CLI.

```bash
gcloud scc findings bulk-mute --organization=ORG_ID ...
```

Refer to the [Security Command Center documentation](https://cloud.google.com/security-command-center/docs) for the full import flow.

---

## CLI reference

See [CLI reference](../cli-reference.md) for all scanner flags (`--severity`, `--offline`, `--baseline-image`, `--sbom`, etc.).
