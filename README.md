# OKE Security Scanner

Automated vulnerability scanning for Docker images deployed in Oracle Kubernetes Engine (OKE) with OpenTelemetry observability.

## Features

| Feature | OKE Specific | Description |
| ------- | ------------ | ----------- |
| Security Scanner | No | Discovers all images in the K8s cluster and scans each with Trivy |
| OCIR Image Cleanup | Yes | Deletes old OCIR tags beyond a configurable `keep_count`, while protecting the deployed tag, `latest`, and any multi-arch sub-manifest digests referenced by kept tags |
| Orphan Manifest Cleanup | Yes | Detects and removes `unknown@sha256:...` platform manifests in OCIR whose digest is no longer referenced by any tagged manifest list |
| Cache Management | No | Automatic cleanup of Trivy image cache after each scan to minimize disk usage |

## Install and Usage

Install and run locally:

```
$ pip install .
$ python -m src.main
```

See [DEVELOPMENT.md](./DEVELOPMENT.md) for full local setup instructions (including the `[dev]` extras for running tests / linting).

Or use the docker build:

```
$ docker build .
```

### Running in Kubernetes

The [`k8s/`](./k8s) folder ships example manifests:
- **`rbac.yaml`** — `ServiceAccount` + read-only `ClusterRole` (pods, namespaces).
- **`cronjob.yaml`** — daily CronJob that mounts three Secrets: `security-scanner-config` (env-var overrides), `security-scanner-oci-config` (`~/.oci/config` + API key), and `security-scanner-docker-config` (`~/.docker/config.json`).
- **`secret-example.yaml`** — template for all three Secrets; copy, fill in values, and apply.

## Authentication

### Kubernetes
For kubernetes auth, you can use local auth creds or give a pod permissions to view the deployed images. See the [k8s](./k8s) folder for example auth roles.

### OCI SDK

The scanner uses the OCI Python SDK for OCIR operations. It automatically derives:
- **OCI Registry URL** from the region in your OCI config (e.g., `us-ashburn-1` → `iad.ocir.io`)
- **OCI Namespace** from the Object Storage API

Configure your OCI credentials in `~/.oci/config`:

```ini
[DEFAULT]
user=ocid1.user.oc1..your-user-ocid
fingerprint=your:fingerprint:here
tenancy=ocid1.tenancy.oc1..your-tenancy-ocid
region=us-ashburn-1
key_file=~/.oci/oci_api_key.pem
```

### Docker Registry (`~/.docker/config.json`)

Docker credentials from `~/.docker/config.json` are used in two places:
- **Trivy** uses them to pull images for vulnerability scanning.
- **Image Cleanup** uses them to fetch manifests via the Docker V2 API. When a kept image is a manifest list (multi-arch), the scanner reads its sub-manifests and protects them from deletion, preventing "manifest unknown" pull errors in the cluster.

## Cache Management

The scanner automatically manages Trivy's cache to minimize disk usage, which is important when running in Kubernetes with ephemeral storage.

After each image scan, the scanner removes the `fanal/` directory (cached image layers) while preserving:
- `db/` - Vulnerability database (~50MB, updated once per run)
- `java-db/` - Java vulnerability index

This approach:
- Prevents disk exhaustion when scanning many large images
- Avoids re-downloading the vulnerability database for each scan
- Ensures cleanup happens even if scans fail or timeout

The Trivy cache is located at `~/.cache/trivy/` (or `$TRIVY_CACHE_DIR` if set).

## Configuration

### Environment Variables

All configuration is provided via Kubernetes secrets as environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OTLP_ENDPOINT` | No | `http://localhost:4317` | OTLP collector endpoint |
| `OTLP_INSECURE` | No | `true` | Use insecure gRPC connection |
| `OTLP_METRICS_ENABLED` | No | `false` | Enable OTLP metrics export |
| `OTLP_LOGS_ENABLED` | No | `false` | Enable OTLP logs export |
| `TRIVY_SEVERITY` | No | `CRITICAL,HIGH` | Vulnerability severities to report |
| `TRIVY_TIMEOUT` | No | `300` | Scan timeout in seconds |
| `TRIVY_PLATFORM` | No | (auto) | Target platform for Trivy scans (e.g. `linux/amd64`) |
| `SCAN_NAMESPACES` | No | (all) | Comma-separated namespaces to scan |
| `EXCLUDE_NAMESPACES` | No | `kube-system,...` | Namespaces to exclude |
| `DISCORD_WEBHOOK_URL` | No | (disabled) | Discord webhook URL for scan notifications |
| `OCIR_CLEANUP_ENABLED` | No | `false` | Enable automatic deletion of old OCIR commit hash tags |
| `OCIR_CLEANUP_KEEP_COUNT` | No | `5` | Number of recent commit hash tags to keep per repository |
| `OCIR_EXTRA_REPOSITORIES` | No | `''` | Check extra repos for old images to remove |
| `ENABLE_SCAN` | No | `true` | Run the Trivy vulnerability scan phase |
| `ENABLE_CLEANUP` | No | `true` | Run the OCIR tag + orphan-manifest cleanup phase |
| `CLEANUP_REPO` | No | `''` | Scope the cleanup phase to one OCIR repo (namespace-qualified, e.g. `tnoff/discord_bot`) |


## Phase toggles and on-push cleanup

The scanner has two independent phases — Trivy scan and OCIR cleanup —
each gated by an env var (`ENABLE_SCAN` / `ENABLE_CLEANUP`, both default
`true`). The daily CronJob runs both. Producer pipelines that want to
prune old tags as soon as they push a new image can fire a one-off Job
derived from the CronJob template with `ENABLE_SCAN=false`:

```bash
kubectl -n default create job "cleanup-${REPO}-${TAG}" \
  --from=cronjob/security-scanner --dry-run=client -o json \
| jq '.spec.template.spec.containers[0].env += [
    {"name":"ENABLE_SCAN","value":"false"},
    {"name":"CLEANUP_REPO","value":"'"$OCIR_REPO"'"},
    {"name":"OCIR_CLEANUP_ENABLED","value":"true"}
  ]' \
| kubectl apply -f -
```

Setting `CLEANUP_REPO` scopes the cleanup phase to a single OCIR repo;
unset, cleanup sweeps every image deployed in the cluster. The
currently-deployed tag is always protected — at push time the cluster
is still running the old tag, so the deployed-image protection in
`get_old_ocir_images` catches it.

[`k8s/rbac-cleanup-trigger.yaml`](./k8s/rbac-cleanup-trigger.yaml)
provides a Role and RoleBinding granting a CI ServiceAccount the
minimum permissions to spawn this Job (default subjects: `gitlab-runner`
SA in the `gitlab-runner` namespace — adjust to match your setup).

At least one of `ENABLE_SCAN` / `ENABLE_CLEANUP` must be `true`; a
`Config` with both off (or `CLEANUP_REPO` set with cleanup disabled)
fails fast at startup.

## Required Permissions

To enable OCIR cleanup, the OCI user/principal must have the `manage repos in compartment <name>` permission for each compartment containing OCIR repositories. Read-only operations (listing tags, resolving manifests) only require `inspect repos` / `read repos`.

## Reporting

Console logs are enabled by default; logs and metrics can additionally be exported via OTLP (tracing is not wired in).

Setting `DISCORD_WEBHOOK_URL` enables Discord notifications for the scan report, cleanup recommendations / results, and orphan-manifest deletions.