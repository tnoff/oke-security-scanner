# Development

## Prerequisites

- Python 3.11+
- [Trivy](https://trivy.dev/latest/getting-started/installation/) installed and on `$PATH`
- OCI config (`~/.oci/config`) with credentials for the tenancy you're targeting
- A kubeconfig with access to the OKE cluster you want to scan

## Setup

Scan, cleanup and secret-age-tracker are separate installable packages now
(see `docs/AGENTS.md`'s File Structure). To work on the scanner:

```bash
pip install -e ".[dev]" -e packages/core[telemetry] -e packages/scan
```

To also work on cleanup or secret-age-tracker:

```bash
pip install -e packages/ocir_cleanup -e packages/secret_age
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

Scan and cleanup are separate processes now, each with its own env vars --
no shared `Config`. The tables below are the scanner's; see
`packages/ocir_cleanup/src/ocir_cleanup/config.py` for cleanup's own (same OTLP/
namespace shape, plus the OCIR cleanup knobs, minus Trivy). All variables
are optional and fall back to the defaults shown below.

### OTLP / OpenTelemetry

| Variable | Default | Description |
|---|---|---|
| `OTLP_ENDPOINT` | `http://localhost:4317` | gRPC endpoint for the OTLP collector |
| `OTLP_INSECURE` | `true` | Disable TLS for the OTLP connection |
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

Cleanup-only (`packages/ocir_cleanup`, not the scanner) — listed here for
reference since both packages' Config share the OTLP/namespace shape above:

| Variable | Default | Description |
|---|---|---|
| `OCIR_CLEANUP_ENABLED` | `false` | Delete old images (dry-run when `false`) |
| `OCIR_CLEANUP_KEEP_COUNT` | `5` | Number of most-recent tags to keep per repository |
| `OCIR_EXTRA_REPOSITORIES` | _(empty)_ | Comma-separated extra OCIR repos to include in cleanup |
| `CLEANUP_PROTECT_TAGS_REGEX` | _(empty)_ | Tags whose name fully matches are excluded from the deletion pool |
| `CLEANUP_GROUP_BY_REGEX` | _(empty)_ | When set, the candidate pool is grouped by the first capture group and `keep_count` is applied per group |
| `CLEANUP_REPO` | _(empty)_ | Scope the run to one OCIR repo, e.g. `tnoff/discord_bot` (see README) |

## Running locally

```bash
export KUBECONFIG=~/.kube/config
# set any other variables you need ...

python -m scan   # scanner
python -m ocir_cleanup    # OCIR cleanup (pip install -e packages/ocir_cleanup first)
```
