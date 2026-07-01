# Tekton CI Integration

Run docker-scanner as a Tekton Task inside your Kubernetes cluster.
The Task writes SARIF, Markdown, and HTML reports to a bound workspace (PVC),
so you can store them, copy them to object storage, or inspect them with
`kubectl cp` after the run.

---

## Prerequisites

- **Tekton Pipelines v0.50 or later** installed in the cluster.
  Quick install (latest stable):
  ```sh
  kubectl apply --filename \
    https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
  ```
  Verify:
  ```sh
  kubectl get pods -n tekton-pipelines
  ```

- **`kubectl`** configured to talk to the target cluster
  (`kubectl cluster-info` should return a live endpoint).

- **`tkn` CLI** (optional but recommended for log streaming and run inspection).
  Install: <https://tekton.dev/docs/cli/>

- **The scanner image** built and pushed to a registry the cluster can pull from.
  Open `ci/tekton/scanner-task.yaml` and replace the `image: docker-scanner:latest`
  placeholder with your fully-qualified image reference, e.g.:
  ```
  image: registry.example.com/docker-scanner:v1.2.3
  ```

---

## Apply the Task

```sh
kubectl apply -f ci/tekton/scanner-task.yaml
```

Verify the Task was registered:

```sh
kubectl get task docker-scanner
# NAME             AGE
# docker-scanner   5s
```

---

## One-shot scan with a TaskRun

Create a TaskRun YAML (or use `tkn task start`) to trigger a single scan
without a full pipeline.

```yaml
# taskrun-example.yaml
apiVersion: tekton.dev/v1
kind: TaskRun
metadata:
  generateName: docker-scanner-run-
spec:
  taskRef:
    kind: Task
    name: docker-scanner
  params:
    - name: image-ref
      value: "registry.example.com/myapp:v1.2.3"
    - name: fail-on-severity
      value: "CRITICAL,HIGH"
    - name: output-formats
      value: "sarif,markdown,html"
  workspaces:
    - name: reports
      # Use an emptyDir for a quick one-shot run.
      # Replace with a PVC reference to persist reports after the pod exits.
      emptyDir: {}
```

Apply and watch:

```sh
kubectl apply -f taskrun-example.yaml

# Stream logs as the step runs
tkn taskrun logs --last --follow
```

Or start interactively with the `tkn` CLI:

```sh
tkn task start docker-scanner \
  --param image-ref=registry.example.com/myapp:v1.2.3 \
  --param fail-on-severity=CRITICAL,HIGH \
  --workspace name=reports,emptyDir={} \
  --showlog
```

---

## Wire into the Pipeline

`ci/tekton/scanner-pipeline.yaml` defines a three-stage Pipeline:

| Stage | What it does |
|-------|-------------|
| `git-clone` | Clones the source repository |
| `build` | Builds and pushes the image with Kaniko |
| `scan` | Runs docker-scanner against the pushed image |
| `notify-success` / `notify-failure` | Sends a webhook notification with the outcome |

Apply both manifests:

```sh
kubectl apply -f ci/tekton/scanner-task.yaml
kubectl apply -f ci/tekton/scanner-pipeline.yaml
```

### Create a PVC for scan reports

Reports need to survive the pod lifecycle. Create a PVC before running the
pipeline:

```sh
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: scan-reports-pvc
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
EOF
```

### Trigger a PipelineRun

Copy the commented-out `PipelineRun` block from the bottom of
`ci/tekton/scanner-pipeline.yaml` into its own file, fill in the values, and
apply it:

```sh
kubectl apply -f my-pipelinerun.yaml

# Watch status
tkn pipelinerun logs --last --follow
```

How findings fail the pipeline: the `scan` task exits non-zero when
vulnerabilities at or above `fail-on-severity` are found. Tekton marks the
Task as **Failed**, which propagates to the PipelineRun status. The
`notify-failure` step in the `finally` block fires regardless, so the team
always receives an alert.

---

## Pass registry credentials

The scanner needs pull access to private registries. Supply credentials through
a Kubernetes Secret so they never appear in plain-text YAML or logs.

### Create the Secret

```sh
kubectl create secret generic registry-credentials \
  --from-literal=username=<your-registry-username> \
  --from-literal=password=<your-registry-token-or-password>
```

For registries that use a Docker config file (e.g. ECR, GCR, Artifact Registry):

```sh
kubectl create secret docker-registry registry-dockerconfig \
  --docker-server=registry.example.com \
  --docker-username=<user> \
  --docker-password=<token>
```

### How the Task uses it

`scanner-task.yaml` maps the Secret values into environment variables via
`secretKeyRef`. The scanner reads `REGISTRY_USERNAME` and `REGISTRY_PASSWORD`
at runtime:

```yaml
env:
  - name: REGISTRY_USERNAME
    valueFrom:
      secretKeyRef:
        name: registry-credentials
        key: username
  - name: REGISTRY_PASSWORD
    valueFrom:
      secretKeyRef:
        name: registry-credentials
        key: password
```

If you need to change the Secret name, edit those two `secretKeyRef.name`
fields in `scanner-task.yaml` and re-apply the Task.

---

## View results

### Stream logs during the run

```sh
# TaskRun
tkn taskrun logs --last --follow

# PipelineRun
tkn pipelinerun logs --last --follow
```

### Inspect the run status after it finishes

```sh
tkn taskrun describe --last
tkn pipelinerun describe --last
```

### Copy reports out of the workspace

Tekton does not have a built-in SARIF viewer. To access the report files:

**Option A — `kubectl cp` from the pod while it is still running**

```sh
# Find the pod name
kubectl get pods -l tekton.dev/taskRun=<taskrun-name>

# Copy the reports directory to your local machine
kubectl cp <pod-name>:/workspace/reports ./scan-reports
```

**Option B — Bind a PVC and copy reports in a final step**

If you use a PVC for the `reports` workspace, add a `finally` task to the
pipeline that uploads the PVC contents to object storage (S3, GCS, Azure Blob):

```yaml
finally:
  - name: upload-reports
    taskSpec:
      workspaces:
        - name: reports
      steps:
        - name: upload
          image: amazon/aws-cli:2.15.0   # or google/cloud-sdk, azcli, etc.
          script: |
            aws s3 cp /workspace/reports/ s3://my-bucket/scan-reports/$(context.pipelineRun.name)/ --recursive
    workspaces:
      - name: reports
        workspace: reports
```

**Option C — Read from the PVC via a separate pod**

```sh
kubectl run report-reader --rm -it \
  --image=busybox \
  --overrides='{"spec":{"volumes":[{"name":"r","persistentVolumeClaim":{"claimName":"scan-reports-pvc"}}],"containers":[{"name":"c","image":"busybox","command":["sh"],"volumeMounts":[{"mountPath":"/reports","name":"r"}]}]}}' \
  -- sh -c "ls /reports && cat /reports/report.md"
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `ImagePullBackOff` on the scan step | Wrong scanner image reference | Update `image:` in `scanner-task.yaml` |
| `401 Unauthorized` when pulling target image | Registry credentials missing or wrong | Check the Secret values; confirm `REGISTRY_USERNAME`/`REGISTRY_PASSWORD` env vars are set |
| Task succeeds but no reports in workspace | Wrong `--output-dir` path | Ensure workspace is bound; check step logs for path errors |
| Pipeline stuck in `Running` | PVC not bound (no available PV) | Check `kubectl get pvc`; ensure a StorageClass can provision the PV |

---

## See also

- [CLI Reference](../cli-reference.md) — full list of `scanner scan` flags,
  including all `--format` and `--fail-on-severity` options
- [Tekton Pipelines documentation](https://tekton.dev/docs/pipelines/)
- [Tekton Hub — task catalog](https://hub.tekton.dev/)
