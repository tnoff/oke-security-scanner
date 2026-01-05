# AI Agent Context for OKE Security Scanner

This document provides context for AI agents (Claude, GPT, etc.) working on this codebase.

## Project Overview

**Purpose:** Automated vulnerability scanning for Docker images deployed in Oracle Kubernetes Engine (OKE) clusters.

**Execution Model:** Runs as a Kubernetes CronJob that:
1. Updates Trivy vulnerability database
2. Queries Kubernetes API to discover all deployed container images
3. Pulls images from Oracle Container Image Registry (OCIR) using provided credentials
4. Scans images with Trivy for vulnerabilities
5. Checks for image version updates across multiple registries (OCIR, Docker Hub, GitHub Container Registry)
6. Identifies old OCIR commit hash tags for cleanup and optionally deletes them
7. Exports observability data (logs, traces, metrics) via OpenTelemetry Protocol (OTLP)
8. Sends Discord notifications with vulnerability, version update, and cleanup reports

**Target Environment:**
- Oracle Kubernetes Engine (OKE)
- Oracle Container Image Registry (OCIR)
- LGTM observability stack (Loki, Grafana, Tempo, Mimir)

## Key Architectural Decisions

### Trivy Update Strategy (Option 3)
The project uses **Option 3** for Trivy management:
- **Bundles a stable Trivy binary** in the Docker image during build
- **Updates vulnerability database at runtime** before each scan
- **Falls back to cached database** if update fails or times out
- **Database size:** ~200MB, updated daily by Trivy maintainers

**Why:** Balances having latest CVE data with stable scanner binary and graceful degradation.

### OCIR Authentication
OKE clusters do **NOT** support standard Kubernetes service accounts for image pulls. Therefore:
- OCIR credentials are stored in Kubernetes secrets
- Credentials are mounted as environment variables
- Format: `${OCI_USERNAME}` = `tenancy/username`, `${OCI_TOKEN}` = auth token
- Same credentials used for image pushes in the related `github-workflows` repository

**Version Checking:**
- Uses OCI Python SDK (`oci==2.164.2`) instead of HTTP API
- Requires OCI SDK configuration at `~/.oci/config` or via environment variables
- Authenticates via `oci.config.from_file()` for config file authentication
- More reliable than HTTP Basic auth and provides better performance

### OpenTelemetry Pattern
**Critical:** All modules follow a consistent OTLP integration pattern:

```python
from logging import getLogger
from opentelemetry.sdk._logs import LoggingHandler
from opentelemetry import trace

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)

class MyClass:
    def __init__(self, cfg: Config, logger_provider):
        self.cfg = cfg
        if logger_provider:  # Check before adding handler
            logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

    def my_method(self):
        with tracer.start_as_current_span("operation-name") as span:
            # Work here
            span.set_attribute("key", "value")
            span.set_attribute("operation.success", True)
```

**Key points:**
- Use standard Python `logging.getLogger()`, NOT structlog
- Pass `logger_provider` from `setup_telemetry()` to all modules (may be `None` if disabled)
- Check for `None` before adding `LoggingHandler` in `__init__` methods
- Wrap significant operations in tracing spans (NoOpTracer used automatically when disabled)
- Set meaningful span attributes for observability
- Use `trace.get_tracer(__name__)` at module level
- OTLP components can be individually disabled via environment variables

### Metrics Strategy
**Simplified to single gauge metric:**

```python
meter.create_gauge(
    "image_scan",
    description="Current vulnerability count per image by severity",
    unit="1",
)
```

**Usage:**
```python
if self.metrics:  # Check for None when metrics disabled
    metrics["scan_total"].set(
        vulnerabilities.get("CRITICAL", 0),
        {"image": image, "severity": "critical"}
    )
```

**Attributes:** `image` (string), `severity` (string: "critical", "high", "medium", "low")

**Note:** `create_metrics()` returns `None` when `meter_provider` is `None` (metrics disabled). Always check for `None` before using.

**Why:** Provides current state view per image, simpler than multiple metrics, easier alerting.

## File Structure

```
oke-security-scanner/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point, orchestrates scanning workflow
│   ├── config.py            # Environment variable configuration
│   ├── telemetry.py         # OpenTelemetry setup (traces, metrics, logs)
│   ├── k8s_client.py        # Kubernetes API client for image discovery
│   ├── scanner.py           # Trivy scanner wrapper
│   ├── registry_client.py   # Multi-registry client for version checking
│   ├── version_reporter.py  # Version update report generation
│   └── discord_notifier.py  # Discord webhook notifications
├── k8s/                  # Kubernetes manifests (EXAMPLES - customize before use)
│   ├── rbac.yaml         # ServiceAccount, ClusterRole, ClusterRoleBinding
│   ├── cronjob.yaml      # CronJob definition (schedule: daily at 2 AM UTC)
│   └── secret-example.yaml  # Secret template (DO NOT COMMIT ACTUAL SECRETS)
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions: build & push to OCIR on main branch
├── Dockerfile            # Multi-stage build with Trivy installed
├── requirements.txt      # Python dependencies
├── VERSION               # Semantic version (e.g., 0.0.1)
├── README.md             # User-facing documentation
└── AGENTS.md             # This file
```

## Important Implementation Details

### src/telemetry.py
**Purpose:** Initialize OpenTelemetry with OTLP exporters based on configuration

**Function signature:** `setup_telemetry(cfg: Config) -> tuple[Optional[TracerProvider], Optional[MeterProvider], Optional[LoggerProvider]]`

**Returns:** Tuple of providers (each may be `None` if disabled via config)

**Key functions:**
- `setup_telemetry(cfg)` - Conditionally configures OTLP exporters for traces, metrics, logs based on config flags
- `create_metrics(meter_provider)` - Creates the `image_scan` gauge metric, returns `None` if meter_provider is `None`

**Conditional initialization:**
- Checks `cfg.otlp_traces_enabled`, `cfg.otlp_metrics_enabled`, `cfg.otlp_logs_enabled`
- Returns `None` for disabled components
- All code safely handles `None` providers (NoOp pattern or explicit checks)

**Resource detection:** Uses `OTELResourceDetector()` for automatic resource attributes

### src/main.py
**Purpose:** Entry point and orchestration

**Flow:**
1. Load configuration from environment variables
2. Setup OpenTelemetry (conditionally based on config flags)
3. Initialize scanner and Kubernetes client (passing logger_provider which may be None)
4. Update Trivy database
5. Discover images from cluster
6. Scan each image for vulnerabilities
7. Check for version updates across registries
8. Generate version update report
9. Identify OCIR cleanup recommendations
10. Delete old OCIR images (if OCIR_CLEANUP_ENABLED=true)
11. Send Discord notifications (if configured)
12. Exit with code 1 if critical vulnerabilities found, 0 otherwise

**Note:** Root span (`security-scan`) only created if traces are enabled. When disabled, operations still traced via NoOpTracer (safe, no-op).

### src/scanner.py
**Purpose:** Wrapper for Trivy CLI

**Key methods:**
- `update_database()` - Updates Trivy vulnerability DB, graceful fallback on failure
- `scan_image(image)` - Scans image, returns vulnerability counts by severity
- `_parse_vulnerabilities(results)` - Parses Trivy JSON output

**Trivy command:**
```bash
trivy image --format json --severity <severities> --timeout <timeout> --quiet <image>
```

**Spans:** `update-trivy-db`, `scan-image`

### src/k8s_client.py
**Purpose:** Kubernetes API client for discovering deployed images

**Key methods:**
- `get_all_images()` - Main entry point, returns set of unique image names
- `_get_namespaces()` - Gets namespaces to scan (configured or discovered with exclusions)
- `_get_namespace_images(namespace)` - Extracts images from pods (regular + init containers)

**Config handling:**
- Tries `load_incluster_config()` first (when running in K8s)
- Falls back to `load_kube_config()` for local development

**Spans:** `init-k8s-client`, `get-all-images`, `get-namespaces`, `get-namespace-images`

### src/config.py
**Purpose:** Configuration from environment variables

**Environment variables:**
- `OCI_REGISTRY` - OCIR URL (e.g., iad.ocir.io)
- `OCI_USERNAME` - OCIR username (format: tenancy/username)
- `OCI_TOKEN` - OCIR auth token
- `OCI_NAMESPACE` - OCIR namespace
- `OTLP_ENDPOINT` - OTLP collector endpoint (default: http://localhost:4317)
- `OTLP_INSECURE` - Use insecure connection (default: true)
- `OTLP_TRACES_ENABLED` - Enable OTLP trace export (default: true)
- `OTLP_METRICS_ENABLED` - Enable OTLP metrics export (default: true)
- `OTLP_LOGS_ENABLED` - Enable OTLP logs export (default: true)
- `TRIVY_SEVERITY` - Severities to report (default: CRITICAL,HIGH)
- `TRIVY_TIMEOUT` - Scan timeout in seconds (default: 300)
- `SCAN_NAMESPACES` - Comma-separated namespaces to scan (optional)
- `EXCLUDE_NAMESPACES` - Namespaces to exclude (default: kube-system,kube-public,kube-node-lease)
- `DISCORD_WEBHOOK_URL` - Discord webhook URL for scan notifications (optional)
- `OCIR_CLEANUP_ENABLED` - Enable automatic deletion of old OCIR commit hash tags (default: false)
- `OCIR_CLEANUP_KEEP_COUNT` - Number of recent commit hash tags to keep per repository (default: 5)

**Validation:** The `validate()` method checks required fields are present.

### src/registry_client.py
**Purpose:** Multi-registry client for checking image version updates

**Key methods:**
- `check_for_updates(image)` - Checks if newer version exists for given image
- `get_image_tags(registry, repository)` - Fetches all tags from registry API
- `get_image_creation_date(registry, repository, tag)` - Gets image creation date (from cache or manifest)
- `parse_image_name(image)` - Parses image into registry, repository, and tag components
- `parse_version(tag)` - Parses semver or commit hash tags
- `get_latest_version(registry, repository, tags)` - Determines latest available version
- `_get_ocir_images_via_sdk(repository)` - Fetches OCIR images using OCI SDK with caching
- `get_cleanup_recommendations(images, keep_count)` - Identifies old OCIR commit hash tags for deletion
- `delete_ocir_images(cleanup_recommendations)` - Deletes old OCIR images by OCID
- `_delete_repository_tags(repository, tags_to_delete)` - Helper for deleting tags from a single repository

**Supported registries:**
- **OCIR**: Oracle Container Image Registry (authenticated via OCI SDK with config file)
- **Docker Hub**: Public registry using Docker Hub API v2
- **GitHub Container Registry (ghcr.io)**: Public images via standard Docker v2 API

**OCIR Implementation:**
- Uses OCI Python SDK (`oci.artifacts.ArtifactsClient`)
- Authenticates via `~/.oci/config` or environment variables (see OCI SDK docs)
- Calls `list_container_images()` API with tenancy-level compartment ID
- Caches image data (tag, created_at, digest) to avoid repeated API calls
- Single API call per repository provides all tags and metadata

**Version comparison strategies:**
- **Semver tags** (v1.2.3, 1.2.3): Parsed and compared by major.minor.patch
- **Commit hash tags** (abc123): Compared by image creation date from manifest
- **Major update detection**: Flags when major version increases (breaking changes expected)

**Spans:** `check-for-updates`, `get-image-tags`, `get-image-manifest`

**Authentication:**
- OCIR: Uses OCI SDK with config file authentication (`oci.config.from_file()`)
- Docker Hub: Fetches bearer token from auth.docker.io
- GitHub Container Registry: Public access (no auth required)

**Caching:**
- OCIR image data cached in `_ocir_image_cache` dict
- Keyed by repository name
- Reduces API calls for version checking (single call per repository)

**OCIR Cleanup:**
- `get_cleanup_recommendations()` identifies old commit hash tags for deletion
- Preserves: tags in use, last N commit hash tags (configurable via `keep_count`), semver tags, 'latest' tag
- Returns dict mapping repository names to cleanup info (tags_in_use, tags_to_keep, tags_to_delete)
- `delete_ocir_images()` deletes tags by OCID using `artifacts_client.delete_container_image()`
- `_delete_repository_tags()` handles deletion for a single repository (finds OCIDs, deletes, logs results)
- Deletion is disabled by default (requires `OCIR_CLEANUP_ENABLED=true`)

### src/version_reporter.py
**Purpose:** Generate formatted reports for image version updates and OCIR cleanup recommendations

**VersionReporter class:**
- `generate_report(update_results)` - Creates formatted console report with MAJOR and minor/patch sections
- `log_summary(update_results)` - Logs summary of update check results
- `_format_update_entry(result)` - Formats individual update entry with version diff

**CleanupReporter class:**
- `generate_report(cleanup_recommendations)` - Creates formatted console report for OCIR cleanup
- `log_summary(cleanup_recommendations)` - Logs summary of cleanup recommendations
- Shows repository name, tag counts (in use, to keep, deletable), and oldest tags with age

**Report structure:**
- **MAJOR VERSION UPDATES**: Breaking changes expected (sorted by image)
- **Minor/Patch Version Updates**: Non-breaking updates (sorted by image)
- **OCIR Cleanup Recommendations**: Old tags to delete with age information (sorted by repository)
- Shows current vs latest version, version differences, and age for commit hashes

### src/discord_notifier.py
**Purpose:** Send scan result notifications to Discord webhooks in up to three message blocks

**Key methods:**
- `send_scan_report(scan_results, total_critical, total_high, duration, total_images, update_results, cleanup_recommendations)` - Sends notification with CSV
- `send_cleanup_recommendations(cleanup_recommendations)` - Sends cleanup report as separate message
- `_build_vulnerability_table(results, severity, only_with_fixes)` - Creates formatted table for specific severity level
- `_build_update_table(update_results, only_minor_patch)` - Creates formatted table for version updates
- `_build_cleanup_table(cleanup_recommendations)` - Creates formatted table for cleanup recommendations
- `_generate_csv(results, update_results, cleanup_recommendations)` - Generates CSV with vulnerabilities, version updates, and cleanup
- `_send_message(content, csv_file)` - Sends message via webhook with optional file attachment

**Message flow:**
1. **Block 1 - Vulnerability Results:**
   - Message 1: Summary with CSV attachment (vulnerabilities + version updates + cleanup)
   - Message 2: CRITICAL vulnerabilities table (fixes only)
2. **Block 2 - Version Update Results:**
   - Message 3: Update summary (minor/patch and major counts)
   - Message 4: Minor/Patch updates table (MAJOR updates excluded)
3. **Block 3 - Cleanup Recommendations** (if any):
   - Message 5: Cleanup summary and table with repository details

**Features:**
- Up to three separate message blocks for clarity (vulnerabilities, updates, cleanup)
- Critical vulnerabilities **with fixes** displayed for immediate action
- Version updates categorized as MAJOR, Minor, Patch, or Commit Hash
- OCIR cleanup recommendations showing deletable tags with age information
- CSV includes vulnerabilities, version updates, **and** cleanup recommendations in separate sections
- Semver parsing for proper version comparison (v1.2.3 format)
- Commit hash comparison by image creation date
- Multi-registry support (OCIR, Docker Hub, GitHub Container Registry)
- 1-second delays between messages to avoid rate limiting
- Uses DapperTable library with custom headers for professional formatting
- Non-blocking: failures logged but don't affect scan execution

**CSV structure:**
```csv
=== VULNERABILITIES ===
Image,CVE,Severity,Fixed Version
...

=== VERSION UPDATES ===
Image,Current Version,Latest Version,Update Type,Age (days),Version Diff
...

=== OCIR CLEANUP RECOMMENDATIONS ===
Repository,Tag,Created Date,Age (days),Status
...
```

**Dependencies:**
- `requests` - HTTP library for webhook calls
- `dappertable` - Table formatting library for Discord code blocks
- `csv` - Standard library for CSV generation
- `io.StringIO` - In-memory file handling for CSV data

**Error handling:**
- All webhook failures are caught and logged as warnings
- Scanner continues normally even if notification fails

## Kubernetes Manifests

### k8s/rbac.yaml
Defines read-only cluster access:
- **ServiceAccount:** `security-scanner`
- **ClusterRole:** Read pods and namespaces across all namespaces
- **ClusterRoleBinding:** Binds role to service account

### k8s/cronjob.yaml
Defines the CronJob:
- **Schedule:** `0 2 * * *` (daily at 2 AM UTC)
- **Image:** Expected to be pushed to OCIR by CI/CD
- **Environment:** Loaded from `security-scanner-secrets`
- **ServiceAccount:** `security-scanner` (for K8s API access)
- **RestartPolicy:** Never (fail fast if errors occur)

### k8s/secret-example.yaml
Template for Kubernetes secret (base64-encoded values). **DO NOT COMMIT ACTUAL SECRETS.**

## Docker Image Build

### Dockerfile
Multi-stage build process:
1. **Base:** Python 3.13-slim (Debian trixie)
2. **System dependencies:** wget, tar, curl
3. **Trivy installation:** Downloaded from GitHub releases (v0.58.2)
   - **IMPORTANT:** Uses GitHub releases, NOT apt repository
   - Apt repository doesn't support Debian trixie
   - Pinned version via ARG for reproducibility
4. **kubectl installation:** Latest stable from dl.k8s.io
5. **Trivy DB pre-download:** Runs `trivy image --download-db-only` during build
6. **Python dependencies:** Installed from requirements.txt
7. **Non-root user:** Runs as user `scanner` (UID 1000)

**Key build command:**
```dockerfile
ARG TRIVY_VERSION=0.58.2
RUN wget -qO trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" && \
    tar -xzf trivy.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy.tar.gz && \
    chmod +x /usr/local/bin/trivy
```

**Why GitHub releases?**
- Trivy apt repository doesn't support newer Debian versions (trixie)
- More reliable across different OS versions
- Explicit version pinning for reproducibility
- Simpler dependencies (no gpg/lsb-release needed)

## CI/CD Workflows

### .github/workflows/ci.yml
**Continuous Integration** - Runs on push to main and pull requests

**Jobs:**
1. **docker-build** - Builds Docker image without pushing
   - Uses Docker Buildx
   - Caches layers with GitHub Actions cache
   - Verifies Dockerfile is valid
   - Runs on ubuntu-24.04

2. **tox** - Runs linting across Python versions
   - Matrix strategy: Python 3.10, 3.11, 3.12, 3.13
   - Installs tox and tox-gh-actions
   - Runs `tox -v` which executes pylint for each version
   - Uses pinned action SHAs for security

**Purpose:** Ensure code quality and Docker image builds before merge

### .github/workflows/cd.yml
**Continuous Deployment** - Runs on PR merge (closed event)

**Jobs:**
1. **tag_build** - Creates git tags from VERSION file
   - Uses github-workflows/tag.yml reusable workflow
   - Requires `contents: write` permission

2. **check_labels** - Verifies PR has required labels
   - Uses github-workflows/check-pr-labels.yml
   - Requires `build-docker` label
   - Must be merged PR

3. **build** - Builds and pushes to OCIR
   - Uses github-workflows/ocir-push.yml
   - Multi-platform: linux/amd64, linux/arm64
   - Tags: VERSION, commit SHA, latest
   - Only runs if check_labels passes

**Purpose:** Automated tagging and deployment to OCIR on merge

## Code Quality

### Linting Configuration

**.pylintrc**
- Disabled warnings: import-error, too-many-instance-attributes, line-too-long, etc.
- Max line length: 120
- Good variable names: i, j, k, e, f, db, ns, cfg

**test-requirements.txt**
- pylint>=3.0.0
- tox>=4.0.0

**tox.ini**
- Environments: py310, py311, py312, py313
- Command: `pylint src/`
- Skip sdist creation
- Named environment: `pylint` for convenience

**Current score:** 10.00/10 on all Python versions

## Common Tasks

### Adding a new configuration option
1. Add field to `Config` class in `src/config.py`
2. Add to `from_env()` method with `os.getenv()`
3. Add validation if required in `validate()`
4. Update `k8s/secret-example.yaml` if stored in secrets
5. Update README.md configuration table

### Adding observability to a new module
1. Import: `from logging import getLogger; from opentelemetry import trace`
2. Module-level: `logger = getLogger(__name__); tracer = trace.get_tracer(__name__)`
3. Accept `logger_provider` parameter in `__init__` (may be None)
4. Add handler with None check: `if logger_provider: logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))`
5. Wrap operations in spans: `with tracer.start_as_current_span("span-name") as span:` (safe even when traces disabled)
6. Set span attributes: `span.set_attribute("key", value)`

### Adding a new metric
1. Define in `create_metrics()` in `src/telemetry.py`
2. Add to returned dictionary (remember function returns None if meter_provider is None)
3. Pass metrics dict to module that needs it
4. Check for None before using: `if self.metrics:` before recording
5. Set/increment metric in code
6. Document in README.md metrics section

### Testing locally
1. Ensure `kubectl` access to OKE cluster
2. Set environment variables (see README.md)
3. Run: `python -m src.main`
4. Requires OTLP collector endpoint reachable

### Building the Docker image
```bash
docker build -t oke-security-scanner:dev .
```

### Running code quality checks
```bash
# Install test dependencies
pip install -r test-requirements.txt

# Run pylint on all source files
pylint src/

# Run pylint on specific file
pylint src/scanner.py

# Run tox to test across multiple Python versions
tox

# Run tox for specific Python version
tox -e py313
```

Configuration is in `.pylintrc` with project-specific settings. Tox configuration is in `tox.ini` and tests Python 3.11, 3.12, and 3.13.

### Running tests
Currently no automated tests. Manual testing via CronJob or one-off Job:
```bash
kubectl create job --from=cronjob/security-scanner manual-scan-$(date +%s)
kubectl logs -f job/manual-scan-<timestamp>
```

## Dependencies

**Python packages (requirements.txt):**
- `kubernetes==34.1.0` - Kubernetes API client
- `oci==2.164.2` - Oracle Cloud Infrastructure SDK for OCIR integration
- `opentelemetry-*` - OTLP SDK, exporters, instrumentation
- `requests` - HTTP library for Discord webhook calls and registry API queries
- `dappertable` - Table formatting for Discord notifications
- System dependencies: Trivy binary (installed in Dockerfile)

**Note:** OCIR version checking uses OCI SDK, Docker Hub and GitHub Container Registry use HTTP API via `requests`

**External services:**
- OCIR for image storage
- OTLP collector (Tempo/Loki/Mimir)
- Kubernetes API
- Discord webhooks (optional)

## Integration with github-workflows Repository

This project shares OCIR credentials and patterns with the `github-workflows` repository:
- Same `OCI_USERNAME`, `OCI_TOKEN`, `OCI_NAMESPACE` secrets
- Similar CI/CD pattern (build on main, push to OCIR with version tags)
- Both use Oracle Cloud Infrastructure

## Security Considerations

- Scanner runs as **non-root user** (UID 1000) in Docker container
- RBAC limited to **read-only** cluster access (pods, namespaces)
- Secrets stored in Kubernetes secrets, not in code or images
- Images pulled with **read-only OCIR credentials**
- Exit code 1 if critical vulnerabilities detected (fail-fast)

## Common Pitfalls

1. **DO NOT** use structlog - use standard `logging.getLogger()`
2. **DO NOT** forget to pass `logger_provider` to modules (may be `None` if OTLP logs disabled)
3. **DO NOT** forget to check for `None` before using `logger_provider` or `metrics`
   - Always use `if logger_provider:` before adding LoggingHandler
   - Always use `if self.metrics:` before recording metrics
4. **DO NOT** commit secrets to git (use k8s/secret-example.yaml as template)
5. **DO NOT** skip span attributes - they're critical for observability
6. **DO NOT** assume OKE supports standard K8s service accounts for image pulls
7. **DO NOT** install Trivy from apt repository - use GitHub releases instead
   - Apt repository doesn't support newer Debian versions
   - Will cause `404 Not Found` errors during build
8. **DO NOT** forget to add missing config fields to `Config.from_env()` method
   - All dataclass fields must be initialized in the class method
   - Missing fields will cause `no-value-for-parameter` errors
9. **DO NOT** forget OCI SDK configuration for OCIR version checking
   - Requires `~/.oci/config` or OCI environment variables
   - Without proper config, OCIR image version checks will fail silently
   - See [OCI SDK Configuration](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)
10. **REMEMBER** Trivy binary is bundled, database updates at runtime
11. **REMEMBER** k8s/ files are examples and must be customized
12. **REMEMBER** to run pylint/tox before committing - CI will fail if code doesn't pass
13. **REMEMBER** OCIR uses OCI SDK, not HTTP API - different from Docker Hub and ghcr.io

## Known Issues and Resolutions

### Issue 1: Docker Build Failure - Trivy Apt Repository
**Error:** `404 Not Found` when installing Trivy from apt repository
**Cause:** Trivy apt repository doesn't support Debian "trixie" (used by Python 3.13-slim)
**Resolution:** Changed to download Trivy binary directly from GitHub releases
**Files affected:** Dockerfile
**Commit context:** Switched from apt-based to GitHub release-based installation

### Issue 2: Pylint Errors - Missing Config Fields
**Error:** `no-value-for-parameter` for `otlp_endpoint` and `otlp_insecure` in Config constructor
**Cause:** Dataclass fields defined but not initialized in `from_env()` method
**Resolution:** Added OTLP configuration fields to `Config.from_env()` return statement
**Files affected:** src/config.py

### Issue 3: Pylint Errors - Unused Imports and Variables
**Errors:**
- Unused import `structlog` in src/telemetry.py
- Unused variable `result` in src/scanner.py
**Resolution:**
- Removed structlog import (not needed, using standard logging)
- Removed unused result variable (subprocess.run with check=True doesn't need result capture)
**Files affected:** src/telemetry.py, src/scanner.py

### Issue 4: Missing logger_provider Parameter
**Error:** `no-value-for-parameter` for `logger_provider` in KubernetesClient constructor
**Cause:** KubernetesClient.__init__ signature updated but call site not updated
**Resolution:** Added `logger_provider` argument to KubernetesClient instantiation in main.py
**Files affected:** src/main.py

### Issue 5: OCIR 401 Unauthorized Errors
**Error:** 401 errors when fetching OCIR image tags via HTTP API
**Cause:** HTTP Basic authentication with OCIR credentials not working reliably
**Resolution:** Switched to OCI Python SDK (`oci.artifacts.ArtifactsClient`) with config file authentication
**Implementation:**
- Uses `oci.config.from_file()` to load `~/.oci/config`
- Calls `list_container_images()` API with tenancy compartment ID
- Caches results to avoid repeated API calls
- Docker Hub and ghcr.io continue using HTTP API (no auth issues)
**Files affected:** src/registry_client.py, requirements.txt
**Benefit:** More reliable authentication + better performance (single API call with all metadata)

## Version Update Checking Implementation Details

### Registry API Patterns

**OCIR (Oracle Container Image Registry):**
- Uses OCI Python SDK (`oci.artifacts.ArtifactsClient`)
- Authentication via `oci.config.from_file()` (reads `~/.oci/config`)
- API call: `list_container_images(compartment_id, repository_name)`
- Returns list of images with tag, created_at, and digest
- Compartment ID obtained from tenancy OCID in OCI config
- **Advantage:** Single API call provides all tags with metadata (no per-tag manifest fetches)
- **Caching:** Results cached in `_ocir_image_cache` dict to avoid repeated calls

**Docker Hub:**
- Tag list uses Hub API v2: `GET https://hub.docker.com/v2/repositories/{repository}/tags`
- Manifest uses Registry v1: `GET https://registry-1.docker.io/v2/{repository}/manifests/{tag}`
- Requires bearer token from `https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull`

**GitHub Container Registry:**
- Uses standard Docker Registry HTTP API V2 (public access)
- Tag list: `GET https://ghcr.io/v2/{repository}/tags/list`
- Manifest: `GET https://ghcr.io/v2/{repository}/manifests/{tag}`

### Version Comparison Logic

**Semver tags (v1.2.3, 1.2.3):**
- Parsed with regex: `^v?(\d+)\.(\d+)\.(\d+).*$`
- Compared by (major, minor, patch) tuple
- Major update: `latest.major > current.major`

**Commit hash tags (abc123, def456):**
- Fetches image manifest to get config digest
- Fetches config blob to get `created` timestamp
- Compares by creation date (ISO 8601 format)
- Newer image = update available

**Mixed environments:**
- If repository has semver tags, prioritizes those for "latest" determination
- Falls back to creation date comparison for non-semver tags
- Doesn't compare semver with commit hash (incompatible)

### Performance Considerations

**API calls per image:**
- **OCIR**: 1 call per repository (via OCI SDK `list_container_images()`)
  - Returns all tags with creation dates in single response
  - Cached for subsequent lookups in same scan run
  - **Fastest option** - no per-tag manifest fetches needed
- **Docker Hub / ghcr.io**: 1 call for tags list + N calls for creation dates
  - N = number of non-semver tags (commit hashes)
  - Can be slow for images with many commit hash tags

**Optimization strategies:**
- OCIR uses OCI SDK with caching (single API call per repository)
- Docker Hub/ghcr.io use requests session for connection pooling
- 10-second timeout per API call
- Failures are logged but don't block scan
- Semver-only images are fastest (no manifest fetching required for Docker Hub/ghcr.io)

### Error Handling

**Registry unavailable:**
- Logs warning and continues to next image
- Returns `None` for update check (skipped)

**Rate limiting:**
- Not currently handled (relies on reasonable scan frequency)
- 1-second delays between Discord messages only

**Unsupported registries:**
- Logs warning for unrecognized registry hostnames
- Skips update check for those images

## Future Considerations

Potential enhancements (not yet implemented):
- Support for additional private registries (Harbor, Artifactory, etc.)
- Configurable actions on vulnerability findings (webhooks, tickets)
- Historical trend analysis for versions and vulnerabilities
- Multi-cluster support
- Automated remediation suggestions
- Integration with admission controllers for prevention
- Caching of registry API responses to reduce API calls
- Parallel version checking for improved performance
