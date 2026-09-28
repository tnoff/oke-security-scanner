# OKE Utilities

Three independent CronJob packages/images for the OKE cluster: image
vulnerability scanning (with OpenTelemetry observability), OCIR tag/manifest
cleanup, and secret-age tracking. Originally a single "security scanner"
repo; renamed once the
[package split](https://github.com/tnoff/docs) (`docs/projects/oke-security-scanner-package-split.md`)
made clear it was really three independent utilities sharing one repo and
one `packages/core`, not phases of one scanner.

## Features

| Feature | OKE Specific | Description |
| ------- | ------------ | ----------- |
| Security Scanner | No | Its own package/image (`packages/scan/`, `python -m scan`). Discovers all images in the K8s cluster and scans each with Trivy. |
| OCIR Image Cleanup | Yes | Its own package/image (`packages/ocir_cleanup/`, `python -m ocir_cleanup`). Deletes old OCIR tags beyond a configurable `keep_count`, while protecting the deployed tag, `latest`, and any multi-arch sub-manifest digests referenced by kept tags. |
| Orphan Manifest Cleanup | Yes | Same package/image as OCIR Image Cleanup. Detects and removes `unknown@sha256:...` platform manifests in OCIR whose digest is no longer referenced by any tagged manifest list. |
| Cache Management | No | Security Scanner only. Automatic cleanup of Trivy image cache after each scan to minimize disk usage. |
| Secret-age Tracker | Yes | Its own package (`packages/secret_age/`) and its own image, with its own CronJob. Reports secrets ≥90 days old across OCI IAM credentials, Kubernetes Secrets — including `docker-apps` SealedSecrets, via the `secret-age-tracker.tnoff/last-rotated` annotation on their target Secret — and operator-tracked admin tfvars (via a layer-1 ledger ConfigMap). See the [docs corpus](https://github.com/tnoff/docs)'s `docs/projects/secret-age-tracker.md` (a separate repo, not this one's own `docs/`). Invoked as `python -m secret_age`. |

All three share `packages/core/` (image discovery, k8s auth, the Discord
webhook client, and — for Security Scanner and OCIR Image Cleanup, which
both run with OpenTelemetry — the OTel setup/teardown helpers).

## Install and Usage

Install and run the scanner locally:

```
$ pip install packages/core packages/scan
$ python -m scan
```

Cleanup and secret-age-tracker are separate installs — see
[`packages/ocir_cleanup/`](./packages/ocir_cleanup) and
[`packages/secret_age/`](./packages/secret_age) respectively (each has its
own `pyproject.toml`; e.g. `pip install packages/core packages/ocir_cleanup &&
python -m ocir_cleanup`).

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for full local setup instructions (including the `[dev]` extras for running tests / linting).

Or use the docker build (one per image):

```
$ docker build -f packages/scan/Dockerfile .            # security scanner
$ docker build -f packages/ocir_cleanup/Dockerfile .    # OCIR cleanup
$ docker build -f packages/secret_age/Dockerfile . # secret-age tracker
```

### Running in Kubernetes

The [`k8s/`](./k8s) folder ships example manifests for the security scanner:
- **`rbac.yaml`** — `ServiceAccount` + read-only `ClusterRole` (pods, namespaces).
- **`cronjob.yaml`** — daily CronJob that mounts three Secrets: `security-scanner-config` (env-var overrides), `security-scanner-oci-config` (`~/.oci/config` + API key), and `security-scanner-docker-config` (`~/.docker/config.json`).
- **`secret-example.yaml`** — template for all three Secrets; copy, fill in values, and apply.

The real deployed manifests for all three CronJobs (including cleanup's and
secret-age-tracker's own) live in `docker-apps`' `apps/security-scanner/`,
not in this repo.

## Authentication

### Kubernetes
For kubernetes auth, you can use local auth creds or give a pod permissions to view the deployed images. See the [k8s](./k8s) folder for example auth roles.

### OCI SDK

`oci` is a dependency of `packages/ocir_cleanup` (and, separately, of
`packages/secret_age`'s OCI IAM reader) — the security scanner itself no
longer depends on it at all. Cleanup uses the OCI Python SDK for OCIR
operations. It automatically derives:
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

Docker credentials from `~/.docker/config.json` are used in two places, each in its own image:
- **Trivy** (security scanner) uses them to pull images for vulnerability scanning.
- **Image Cleanup** (`packages/ocir_cleanup`) uses them to fetch manifests via the Docker V2 API. When a kept image is a manifest list (multi-arch), it reads its sub-manifests and protects them from deletion, preventing "manifest unknown" pull errors in the cluster.

## Cache Management

The scanner automatically manages Trivy's cache to minimize disk usage, which is important when running in Kubernetes with ephemeral storage.

After each image scan, the scanner removes the `fanal/` directory (cached image layers) while preserving:
- `db/` - Vulnerability database (~50MB, updated once per run)
- `java-db/` - Java vulnerability index

This approach:
- Prevents disk exhaustion when scanning many large images
- Avoids re-downloading the vulnerability database for each scan
- Ensures cleanup happens even if scans fail or timeout

The Trivy cache is located at `~/.cache/trivy/` (the Docker image sets `TRIVY_CACHE_DIR` to this by default). Note this is Trivy's own env var, read by the `trivy` binary -- this app's cache-cleanup code does not read it and always cleans `~/.cache/trivy/`, so overriding `TRIVY_CACHE_DIR` away from the default would point Trivy at a location the cleanup logic no longer manages.

## Configuration

### Environment Variables

Scan and cleanup are separate processes/images now, each with its own env
vars — there's no longer a single combined `Config`. Both are provided via
Kubernetes Secrets.

**Security Scanner** (`packages/scan/src/scan/main.py`, `python -m scan`):

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
| `DISCORD_WEBHOOK_URL` | No | (disabled) | Discord webhook URL for the scan report |

**OCIR Cleanup** (`packages/ocir_cleanup/src/ocir_cleanup/main.py`, `python -m ocir_cleanup`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OTLP_ENDPOINT` | No | `http://localhost:4317` | OTLP collector endpoint |
| `OTLP_INSECURE` | No | `true` | Use insecure gRPC connection |
| `OTLP_METRICS_ENABLED` | No | `false` | Enable OTLP metrics export |
| `OTLP_LOGS_ENABLED` | No | `false` | Enable OTLP logs export |
| `SCAN_NAMESPACES` | No | (all) | Comma-separated namespaces to scan for deployed images |
| `EXCLUDE_NAMESPACES` | No | `kube-system,...` | Namespaces to exclude |
| `DISCORD_WEBHOOK_URL` | No | (disabled) | Discord webhook URL for cleanup recommendations / deletion results |
| `OCIR_CLEANUP_ENABLED` | No | `false` | Enable automatic deletion of old OCIR commit hash tags |
| `OCIR_CLEANUP_KEEP_COUNT` | No | `5` | Number of recent commit hash tags to keep per repository (or per group, if `CLEANUP_GROUP_BY_REGEX` is set) |
| `OCIR_EXTRA_REPOSITORIES` | No | `''` | Check extra repos for old images to remove |
| `CLEANUP_PROTECT_TAGS_REGEX` | No | `''` | Tags whose name fully matches are excluded from the deletion pool. Used to protect mutable "channel" tags (e.g. `^\d+\.\d+$` for ci-base-images' `:3.X`). |
| `CLEANUP_GROUP_BY_REGEX` | No | `''` | When set, the candidate pool is grouped by the first capture group and `keep_count` is applied per group. Prevents heavy churn in one group from pushing other groups' tags out of the keep window (e.g. `^(\d+\.\d+)` keeps the last N `:3.X-<sha>` per minor independently). |
| `CLEANUP_REPO` | No | `''` | Scope the run to one OCIR repo (namespace-qualified, e.g. `tnoff/discord_bot`) |

`packages/secret_age/`'s env vars are documented separately — see that
package's `README`/docs project, not here.

## On-push cleanup

Producer pipelines that want to prune old tags as soon as they push a new
image can fire a one-off Job derived from the **cleanup CronJob template**
(not the scanner's — cleanup is a separate image now, so there's no
`ENABLE_SCAN=false` toggle to set):

```bash
kubectl -n default create job "cleanup-${REPO}-${TAG}" \
  --from=cronjob/cleanup-all --dry-run=client -o json \
| jq '.spec.template.spec.containers[0].env += [
    {"name":"CLEANUP_REPO","value":"'"$OCIR_REPO"'"},
    {"name":"OCIR_CLEANUP_ENABLED","value":"true"}
  ]' \
| kubectl apply -f -
```

Setting `CLEANUP_REPO` scopes the run to a single OCIR repo; unset,
cleanup sweeps every image deployed in the cluster. The
currently-deployed tag is always protected — at push time the cluster
is still running the old tag, so the deployed-image protection in
`get_old_ocir_images` catches it.

[`k8s/rbac-cleanup-trigger.yaml`](./k8s/rbac-cleanup-trigger.yaml)
provides a Role and RoleBinding granting a CI ServiceAccount the
minimum permissions to spawn this Job (default subjects: `gitlab-runner`
SA in the `gitlab-runner` namespace — adjust to match your setup).

## Required Permissions

To enable OCIR cleanup, the OCI user/principal used by the **cleanup**
image must have the `manage repos in compartment <name>` permission for
each compartment containing OCIR repositories. Read-only operations
(listing tags, resolving manifests) only require `inspect repos` /
`read repos`.

## Reporting

Console logs are enabled by default for both images; logs and metrics can
additionally be exported via OTLP (tracing is not wired in). Set each
image's own `DISCORD_WEBHOOK_URL` independently — the scanner posts the
scan report, cleanup posts recommendations/deletion results; they are two
separate webhook configs now, not a shared URL with a cleanup-specific
override.