# AI Agent Context for OKE Security Scanner

This document provides context for AI agents (Claude, GPT, etc.) working on this codebase.

## Project Overview

**Purpose:** Automated vulnerability scanning for Docker images deployed in Oracle Kubernetes Engine (OKE) clusters.

**Execution Model:** Runs as a Kubernetes CronJob that:
1. Updates Trivy vulnerability database
2. Queries Kubernetes API to discover all deployed container images
3. Pulls images from Oracle Container Image Registry (OCIR) using provided credentials
4. Scans images with Trivy for vulnerabilities
5. Exports observability data (logs, traces, metrics) via OpenTelemetry Protocol (OTLP)

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
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

    def my_method(self):
        with tracer.start_as_current_span("operation-name") as span:
            # Work here
            span.set_attribute("key", "value")
            span.set_attribute("operation.success", True)
```

**Key points:**
- Use standard Python `logging.getLogger()`, NOT structlog
- Pass `logger_provider` from `setup_telemetry()` to all modules
- Add `LoggingHandler` in `__init__` methods
- Wrap significant operations in tracing spans
- Set meaningful span attributes for observability
- Use `trace.get_tracer(__name__)` at module level

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
metrics["scan_total"].set(
    vulnerabilities.get("CRITICAL", 0),
    {"image": image, "severity": "critical"}
)
```

**Attributes:** `image` (string), `severity` (string: "critical", "high", "medium", "low")

**Why:** Provides current state view per image, simpler than multiple metrics, easier alerting.

## File Structure

```
oke-security-scanner/
├── src/
│   ├── __init__.py
│   ├── main.py           # Entry point, orchestrates scanning workflow
│   ├── config.py         # Environment variable configuration
│   ├── telemetry.py      # OpenTelemetry setup (traces, metrics, logs)
│   ├── k8s_client.py     # Kubernetes API client for image discovery
│   └── scanner.py        # Trivy scanner wrapper
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
**Purpose:** Initialize OpenTelemetry with OTLP exporters

**Returns:** `(tracer, meter, logger_provider)` tuple

**Key functions:**
- `setup_telemetry()` - Configures OTLP exporters for traces, metrics, logs
- `create_metrics(meter)` - Creates the `image_scan` gauge metric

**Resource detection:** Uses `OTELResourceDetector()` for automatic resource attributes

### src/main.py
**Purpose:** Entry point and orchestration

**Flow:**
1. Load configuration from environment variables
2. Setup OpenTelemetry
3. Initialize scanner and Kubernetes client (passing logger_provider)
4. Update Trivy database
5. Discover images from cluster
6. Scan each image
7. Exit with code 1 if critical vulnerabilities found, 0 otherwise

**Root span:** `security-scan` wraps entire operation

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
- `TRIVY_SEVERITY` - Severities to report (default: CRITICAL,HIGH)
- `TRIVY_TIMEOUT` - Scan timeout in seconds (default: 300)
- `SCAN_NAMESPACES` - Comma-separated namespaces to scan (optional)
- `EXCLUDE_NAMESPACES` - Namespaces to exclude (default: kube-system,kube-public,kube-node-lease)

**Validation:** The `validate()` method checks required fields are present.

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
3. Accept `logger_provider` parameter in `__init__`
4. Add handler: `logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))`
5. Wrap operations in spans: `with tracer.start_as_current_span("span-name") as span:`
6. Set span attributes: `span.set_attribute("key", value)`

### Adding a new metric
1. Define in `create_metrics()` in `src/telemetry.py`
2. Add to returned dictionary
3. Pass metrics dict to module that needs it
4. Set/increment metric in code
5. Document in README.md metrics section

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
- `kubernetes` - Kubernetes API client
- `opentelemetry-*` - OTLP SDK, exporters, instrumentation
- System dependencies: Trivy binary (installed in Dockerfile)

**External services:**
- OCIR for image storage
- OTLP collector (Tempo/Loki/Mimir)
- Kubernetes API

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
2. **DO NOT** forget to pass `logger_provider` to modules
3. **DO NOT** commit secrets to git (use k8s/secret-example.yaml as template)
4. **DO NOT** skip span attributes - they're critical for observability
5. **DO NOT** assume OKE supports standard K8s service accounts for image pulls
6. **DO NOT** install Trivy from apt repository - use GitHub releases instead
   - Apt repository doesn't support newer Debian versions
   - Will cause `404 Not Found` errors during build
7. **DO NOT** forget to add missing config fields to `Config.from_env()` method
   - All dataclass fields must be initialized in the class method
   - Missing fields will cause `no-value-for-parameter` errors
8. **REMEMBER** Trivy binary is bundled, database updates at runtime
9. **REMEMBER** k8s/ files are examples and must be customized
10. **REMEMBER** to run pylint/tox before committing - CI will fail if code doesn't pass

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

## Future Considerations

Potential enhancements (not yet implemented):
- Support for private registries beyond OCIR
- Configurable actions on vulnerability findings (webhooks, tickets)
- Historical trend analysis
- Multi-cluster support
- Automated remediation suggestions
- Integration with admission controllers for prevention
