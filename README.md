# OKE Security Scanner

Automated vulnerability scanning for Docker images deployed in Oracle Kubernetes Engine (OKE) with OpenTelemetry observability.

## Features

- 🔍 **Automatic Discovery** - Queries Kubernetes API to find all deployed images
- 🛡️ **Trivy Scanner** - Industry-standard vulnerability scanner with daily DB updates
- 🔄 **Version Update Detection** - Identifies outdated images (semver & commit hash) across multiple registries
- 📊 **OTLP Observability** - Sends logs, traces, and metrics to your LGTM stack
- 🔐 **Multi-Registry Support** - Works with OCIR, Docker Hub, and GitHub Container Registry
- 🎯 **Namespace Filtering** - Scan specific namespaces or exclude system namespaces

## Architecture

```
┌──────────────────────────────────────┐
│   Kubernetes CronJob                 │
│   ┌──────────────────────────────┐   │
│   │  Security Scanner            │   │
│   │  ┌───────────────────────┐   │   │
│   │  │ 1. Update Trivy DB    │   │   │
│   │  │    (latest CVEs)      │   │   │
│   │  └───────────────────────┘   │   │
│   │  ┌───────────────────────┐   │   │
│   │  │ 2. Query K8s API      │   │   │
│   │  │    (discover images)  │   │   │
│   │  └───────────────────────┘   │   │
│   │  ┌───────────────────────┐   │   │
│   │  │ 3. Scan Vulnerabilities│  │   │
│   │  │    (Trivy)            │   │   │
│   │  └───────────────────────┘   │   │
│   │  ┌───────────────────────┐   │   │
│   │  │ 4. Check for Updates  │   │   │
│   │  │    - Query registries │   │   │
│   │  │    - Compare versions │   │   │
│   │  └───────────────────────┘   │   │
│   │  ┌───────────────────────┐   │   │
│   │  │ 5. Send OTLP          │   │   │
│   │  │    - Logs (Loki)      │   │   │
│   │  │    - Traces (Tempo)   │   │   │
│   │  │    - Metrics (Mimir)  │   │   │
│   │  └───────────────────────┘   │   │
│   └──────────────────────────────┘   │
└──────────────────────────────────────┘
```

## Prerequisites

- Kubernetes cluster (OKE)
- OCIR credentials (same as used for image pushes)
- OTLP collector endpoint (Tempo for traces, Loki for logs, Mimir for metrics)
- Kubernetes RBAC permissions to read pods and namespaces

## Quick Start

**Note:** The files in the `k8s/` folder are examples. Review and customize them for your environment before deploying.

### 1. Create Kubernetes Secret

```bash
kubectl create secret generic security-scanner-secrets \
  --from-literal=OCI_REGISTRY="iad.ocir.io" \
  --from-literal=OCI_USERNAME="your-tenancy/your-username" \
  --from-literal=OCI_TOKEN="your-auth-token" \
  --from-literal=OCI_NAMESPACE="your-namespace" \
  --from-literal=OTLP_ENDPOINT="http://tempo.monitoring.svc.cluster.local:4317" \
  --from-literal=OTLP_INSECURE="true" \
  --from-literal=TRIVY_SEVERITY="CRITICAL,HIGH" \
  --from-literal=TRIVY_TIMEOUT="300" \
  --from-literal=EXCLUDE_NAMESPACES="kube-system,kube-public,kube-node-lease" \
  --from-literal=DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/your-webhook-url" \
  --namespace=default
```

Or use the example file:

```bash
cp k8s/secret-example.yaml k8s/secret.yaml
# Edit k8s/secret.yaml with your values
kubectl apply -f k8s/secret.yaml
```

### 2. Deploy RBAC and CronJob

```bash
# Apply RBAC (ServiceAccount, ClusterRole, ClusterRoleBinding)
kubectl apply -f k8s/rbac.yaml

# Deploy CronJob
kubectl apply -f k8s/cronjob.yaml
```

### 3. Test Manual Run

```bash
# Trigger a manual scan
kubectl create job --from=cronjob/security-scanner manual-scan-$(date +%s)

# Watch logs
kubectl logs -f job/manual-scan-<timestamp>
```

## Configuration

### Environment Variables

All configuration is provided via Kubernetes secrets as environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OCI_REGISTRY` | ✅ | - | OCIR URL (e.g., `iad.ocir.io`) |
| `OCI_USERNAME` | ✅ | - | OCIR username (`tenancy/username`) |
| `OCI_TOKEN` | ✅ | - | OCIR auth token |
| `OCI_NAMESPACE` | ✅ | - | OCIR namespace |
| `TRIVY_SEVERITY` | ❌ | `CRITICAL,HIGH` | Vulnerability severities to report |
| `TRIVY_TIMEOUT` | ❌ | `300` | Scan timeout in seconds |
| `SCAN_NAMESPACES` | ❌ | (all) | Comma-separated namespaces to scan |
| `EXCLUDE_NAMESPACES` | ❌ | `kube-system,...` | Namespaces to exclude |
| `DISCORD_WEBHOOK_URL` | ❌ | (disabled) | Discord webhook URL for scan notifications |

### CronJob Schedule

Edit `k8s/cronjob.yaml` to change the scan schedule:

```yaml
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM UTC
```

Common schedules:
- `0 2 * * *` - Daily at 2 AM
- `0 */6 * * *` - Every 6 hours
- `0 0 * * 0` - Weekly on Sunday

## Observability

### Logs (Loki)

Structured JSON logs include:
- Image name and scan results
- Critical vulnerabilities with CVE IDs
- Scan duration and status
- Database update status

Query examples:
```logql
{app="security-scanner"} | json | severity = "CRITICAL"
{app="security-scanner"} | json | image =~ "discord-bot.*"
```

### Traces (Tempo)

Distributed traces show:
- Root span: `security-scan` (entire scan operation)
- Child spans: `scan-image` (per image)
- Sub-spans: `update-trivy-db`, `get-cluster-images`

### Metrics (Mimir/Prometheus)

Single gauge metric tracking current vulnerability counts per image:

```promql
# Current vulnerability count per image
image_scan{image="discord-bot:abc1234", severity="critical"}
image_scan{image="discord-bot:abc1234", severity="high"}

# Example queries:
# Images with critical vulnerabilities
image_scan{severity="critical"} > 0

# Total critical vulnerabilities across all images
sum(image_scan{severity="critical"})

# Images with the most critical vulnerabilities
topk(5, image_scan{severity="critical"})
```

### Grafana Dashboards

Create dashboards showing:
- Vulnerability trends over time
- Images with most critical CVEs
- Scan success rate
- Trivy DB freshness

## Discord Notifications

The scanner sends comprehensive scan results to Discord via webhooks in **two message blocks**. This is optional and enabled when `DISCORD_WEBHOOK_URL` is configured.

### Message Block 1: Vulnerability Scan Results

- **Summary**: Scan duration, image count, vulnerability counts
- **Critical Vulnerabilities Table**: Shows CRITICAL CVEs with available fixes
- **CSV Attachment**: Complete vulnerability and version update report

### Message Block 2: Version Update Results

- **Update Summary**: Counts of minor/patch and major updates available
- **Minor/Patch Updates Table**: Non-breaking updates for easy deployment
- **Note**: MAJOR updates excluded from message (see CSV for full report)

### Features

- Two separate message blocks for clarity (vulnerabilities, then updates)
- Critical vulnerabilities **with available fixes** displayed for immediate action
- Version updates categorized as MAJOR, Minor, Patch, or Commit Hash
- CSV includes **both** vulnerabilities and version updates in separate sections
- Semver parsing for proper version comparison (v1.2.3 format)
- Commit hash comparison by image creation date
- Multi-registry support (OCIR, Docker Hub, GitHub Container Registry)
- Non-blocking: webhook failures don't affect scan execution

### Setup

1. Create a Discord webhook in your server:
   - Go to Server Settings > Integrations > Webhooks
   - Click "New Webhook"
   - Copy the webhook URL

2. Add the webhook URL to your Kubernetes secret:
   ```bash
   kubectl create secret generic security-scanner-secrets \
     --from-literal=DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/your-webhook-url" \
     # ... other configuration ...
   ```

3. The scanner will automatically send notifications after each scan completes

### Example Output

**Message Block 1 - Vulnerabilities:**
```
Security Scan Complete
Scanned: 25 images in 142.3s
Critical: 3 | High: 12

CRITICAL Vulnerabilities:
```Image                         || CVE                 || Fixed
-------------------------------------------------------------
discord-bot:v1.0.0            || CVE-2023-1234       || 1.2.3```
```

**Message Block 2 - Version Updates:**
```
Image Version Updates
Minor/Patch: 5 | Major: 2
(Major updates excluded below, see CSV for full report)

Minor/Patch Updates Available:
```Image                         || Current        || Latest         || Type
-------------------------------------------------------------------------
discord-bot:v1.0.0            || 1.0.0          || 1.2.0          || minor
backup-tool:abc123            || abc123         || def456         || newer```
```

**CSV Sections:**
- **Vulnerabilities**: All CVEs with severity and fix information
- **Version Updates**: All updates (MAJOR + minor/patch) with age and version diff

## Development

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export OCI_REGISTRY="iad.ocir.io"
export OCI_USERNAME="tenancy/username"
export OCI_TOKEN="your-token"
export OCI_NAMESPACE="namespace"

# Run locally (requires kubectl access to cluster)
python -m src.main
```

### Building the Image

```bash
# Build locally
docker build -t oke-security-scanner:dev .

# Test locally
docker run --rm \
  -v ~/.kube/config:/home/scanner/.kube/config:ro \
  -e OCI_REGISTRY="iad.ocir.io" \
  -e OCI_USERNAME="tenancy/username" \
  -e OCI_TOKEN="token" \
  -e OCI_NAMESPACE="namespace" \
  oke-security-scanner:dev
```

### Code Quality

```bash
# Install test dependencies
pip install -r test-requirements.txt

# Run pylint on all source files
pylint src/

# Run pylint on specific file
pylint src/scanner.py

# Run tox to test across multiple Python versions (3.11, 3.12, 3.13)
tox

# Run tox for specific Python version
tox -e py313
```

Pylint configuration is in `.pylintrc` with project-specific settings to match the codebase style. Tox configuration is in `tox.ini`.

### Continuous Integration

GitHub Actions automatically runs CI checks on pull requests and pushes to main:
- **Linting**: Runs pylint across Python 3.11, 3.12, and 3.13
- **Tox**: Executes tox test suite
- **Docker Build**: Verifies the Docker image builds successfully