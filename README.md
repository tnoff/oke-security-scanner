# OKE Security Scanner

Automated vulnerability scanning for Docker images deployed in Oracle Kubernetes Engine (OKE) with OpenTelemetry observability.

## Features

| Feature | OKE Specific | Description |
| ------- | ------------ | ----------- |
| Security Scanner | No | Fetches all images in K8s cluster and runs trivy scanner |
| Image Update Report | No | Checks for new versions of deployed images |
| Image Cleanup | Yes | Cleanup OCIR images that do not match semver versioning |
| OKE Node Image Check | Yes | Reports outdated OKE node/boot images for node pools |
| Cache Management | No | Automatic cleanup of Trivy image cache after each scan to minimize disk usage |

## Install and Usage

Install the requirements locally and run

```
$ pip install requirements.txt
$ python -m src.main
```

Or use the docker build

```
$ docker build .
```

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
| `OTLP_TRACES_ENABLED` | No | `true` | Enable OTLP trace export |
| `OTLP_METRICS_ENABLED` | No | `true` | Enable OTLP metrics export |
| `OTLP_LOGS_ENABLED` | No | `true` | Enable OTLP logs export |
| `TRIVY_SEVERITY` | No | `CRITICAL,HIGH` | Vulnerability severities to report |
| `TRIVY_TIMEOUT` | No | `300` | Scan timeout in seconds |
| `TRIVY_PLATFORM` | No | (auto) | Target platform for Trivy scans (e.g. `linux/amd64`) |
| `SCAN_NAMESPACES` | No | (all) | Comma-separated namespaces to scan |
| `EXCLUDE_NAMESPACES` | No | `kube-system,...` | Namespaces to exclude |
| `DISCORD_WEBHOOK_URL` | No | (disabled) | Discord webhook URL for scan notifications |
| `OCIR_CLEANUP_ENABLED` | No | `false` | Enable automatic deletion of old OCIR commit hash tags |
| `OCIR_CLEANUP_KEEP_COUNT` | No | `5` | Number of recent commit hash tags to keep per repository |
| `OCIR_EXTRA_REPOSITORIES` | No | `''` | Check extra repos for old images to remove |
| `OKE_IMAGE_CHECK_ENABLED` | No | `false` | Enable OKE node image version checking |
| `OKE_CLUSTER_OCID` | No | (required if enabled) | OCID of the OKE cluster to check node images for |


## Required Permissions

To enable OCIR cleanup, the OCI user/principal must have the `manage repos in compartment <name>` permission for each compartment containing OCIR repositories. See the Prerequisites section for full IAM policy details.


## Reporting

Logs enabled to console by default, traces and metrics can also be enabled through OTLP.

Discord webhook can also be provded to send a readable report as well.