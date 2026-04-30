# Development

## Prerequisites

- Python 3.11+
- [Trivy](https://trivy.dev/latest/getting-started/installation/) installed and on `$PATH`
- OCI config (`~/.oci/config`) with credentials for the tenancy you're targeting
- A kubeconfig with access to the OKE cluster you want to scan

## Setup

```bash
pip install -e ".[dev]"
```

## Running tests

Run the full suite (pytest, pylint, bandit):

```bash
tox
```

Or run individual steps:

```bash
tox -e pytest    # tests only
tox -e pylint    # linting only
tox -e bandit    # security scan only
```

## Configuration

The scanner is configured entirely via environment variables. All variables are optional and fall back to the defaults shown below.

### OTLP / OpenTelemetry

| Variable | Default | Description |
|---|---|---|
| `OTLP_ENDPOINT` | `http://localhost:4317` | gRPC endpoint for the OTLP collector |
| `OTLP_INSECURE` | `true` | Disable TLS for the OTLP connection |
| `OTLP_TRACES_ENABLED` | `false` | Export traces |
| `OTLP_METRICS_ENABLED` | `false` | Export metrics |
| `OTLP_LOGS_ENABLED` | `false` | Export logs |

### Trivy

| Variable | Default | Description |
|---|---|---|
| `TRIVY_SEVERITY` | `CRITICAL,HIGH` | Comma-separated severity levels to report |
| `TRIVY_TIMEOUT` | `300` | Per-image scan timeout in seconds |
| `TRIVY_PLATFORM` | _(empty)_ | Target platform (e.g. `linux/amd64`) |

### Scanning

| Variable | Default | Description |
|---|---|---|
| `SCAN_NAMESPACES` | _(all)_ | Comma-separated namespaces to scan; omit to scan all |
| `EXCLUDE_NAMESPACES` | `kube-system,kube-public,kube-node-lease` | Namespaces to skip |

### Discord notifications

| Variable | Default | Description |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | _(disabled)_ | Webhook URL; notifications are skipped if unset |

### OCIR cleanup

| Variable | Default | Description |
|---|---|---|
| `OCIR_CLEANUP_ENABLED` | `false` | Delete old images (dry-run when `false`) |
| `OCIR_CLEANUP_KEEP_COUNT` | `5` | Number of most-recent tags to keep per repository |
| `OCIR_EXTRA_REPOSITORIES` | _(empty)_ | Comma-separated extra OCIR repos to include in cleanup |

### OKE node image check

| Variable | Default | Description |
|---|---|---|
| `OKE_IMAGE_CHECK_ENABLED` | `false` | Check node pools for available image updates |
| `OKE_CLUSTER_OCID` | _(empty)_ | OCID of the OKE cluster to inspect |
| `OKE_REGION` | _(empty)_ | OCI region identifier (e.g. `us-ashburn-1`) |

## Running locally

```bash
export KUBECONFIG=~/.kube/config
export OKE_REGION=us-ashburn-1
# set any other variables you need ...

python -m src.main
```
