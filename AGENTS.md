# AI Agent Context for OKE Security Scanner

Context for AI agents (Claude, GPT, etc.) working on this codebase.

For **what the project does**, **how to install/run it**, **env-var reference**, **authentication setup**, and the **Kubernetes deployment shape**, read [README.md](./README.md). For **local-dev setup** and the **DEV env-var reference**, read [DEVELOPMENT.md](./DEVELOPMENT.md). This file covers only the things an agent needs that aren't in those docs.

## File Structure

```
oke-security-scanner/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point, orchestrates scanning workflow
│   ├── config.py            # Environment variable configuration
│   ├── telemetry.py         # OpenTelemetry setup (metrics + logs only — NO tracing)
│   ├── k8s_client.py        # Kubernetes API client for image discovery
│   ├── scanner.py           # Trivy scanner wrapper
│   ├── registry_client.py   # OCIR cleanup + orphan-manifest detection
│   └── discord_notifier.py  # Discord webhook notifications
├── tests/                # Pytest suite (100% line coverage)
├── k8s/                  # CronJob + RBAC + Secret examples
├── .gitlab-ci.yml        # GitLab CI pipeline
├── Dockerfile            # Two-stage build (trivy-builder + slim runtime)
├── pyproject.toml        # Python deps, build metadata, pylint config
├── tox.ini               # pytest / pylint / bandit envs
├── VERSION               # Semantic version
├── README.md             # User-facing documentation
├── DEVELOPMENT.md        # Local-dev setup
└── AGENTS.md             # This file
```

## Observability Pattern

Logs and metrics are exported via OTLP. **Tracing was deliberately removed** — do not add `tracer.start_as_current_span(...)` blocks back without explicit user direction.

```python
from logging import getLogger
from opentelemetry.instrumentation.logging.handler import LoggingHandler

logger = getLogger(__name__)

class MyClass:
    def __init__(self, cfg: Config, logger_provider):
        self.cfg = cfg
        if logger_provider:  # may be None when OTLP logs disabled
            logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))
```

- Use standard Python `logging.getLogger()` — never `structlog`.
- `logger_provider` and `meter_provider` may both be `None` when their OTLP component is disabled in config. Always check before using.

## Metrics

Single gauge metric (`image_scan`) defined in `telemetry.create_metrics()`. Attributes: `image` (string), `severity` (`critical` | `high`).

`create_metrics()` returns `None` when `meter_provider` is `None`. Always check before recording (`if self.metrics: ...`).

## Important Implementation Details

### `src/telemetry.py`
`setup_telemetry(cfg) -> tuple[Optional[MeterProvider], Optional[LoggerProvider]]`. Each provider is `None` if that OTLP component is disabled. `create_metrics(meter_provider)` returns `None` when its argument is `None`. Resource attributes come from `OTELResourceDetector()`.

### `src/main.py`
Orchestration only. Flow: load config → set up telemetry → update Trivy DB → init K8s/Trivy clients → discover & scan images → optional Discord report → emit metrics → compute & optionally apply OCIR cleanup → compute & optionally apply orphan-manifest cleanup → flush+shutdown providers in `finally`.

The `if __name__ == "__main__":` guard is marked `# pragma: no cover` (standard untestable pattern).

### `src/scanner.py`
- `update_database()` — runs `trivy image --download-db-only` once at startup; logs and continues on timeout/error.
- `scan_image(image)` — invokes Trivy with JSON output, parses CVE results into `ScanResult`.
- `_cleanup_image_cache()` — removes `fanal/` from the Trivy cache after each scan to bound disk usage; the vulnerability DB is preserved.

### `src/k8s_client.py`
- Tries `load_incluster_config()` first, falls back to `load_kube_config()` for local dev.
- `get_all_images()` enumerates namespaces (configured set or all-minus-exclusions), then collects images from regular + init containers across all pods.
- The `Image` dataclass parses `registry / repo_name / tag`, strips digest suffixes (`@sha256:...`), and exposes `is_ocir_image`. There is **no** `Image.version` / semver comparison anymore — don't reintroduce it.

### `src/registry_client.py`
OCIR-only. There is no Docker Hub / ghcr.io version-check logic anymore.

Properties:
- `oci_registry` — derived from the OCI config region.
- `oci_namespace` — fetched (and cached) via Object Storage API.

Key methods:
- `_get_ocir_images_via_sdk(image)` — lists all images in an OCIR repo via `oci.artifacts.ArtifactsClient.list_container_images` (paginated). Cached per repo.
- `_find_repository_compartment(repo)` — searches all accessible compartments for a repo; results cached.
- `_get_docker_auth(image)` — reads `~/.docker/config.json`, handles Basic-vs-Bearer token exchange against the registry's `/v2/` endpoint. Used only for fetching manifest lists.
- `_get_manifest_list_sub_digests(image)` — fetches a manifest list (multi-arch index) via Docker V2 API to enumerate sub-manifest digests; used to protect referenced platform manifests during cleanup.
- `get_old_ocir_images(images, keep_count, extra_repositories)` — returns `CleanupRecommendation`s of old commit-hash tags eligible for deletion, while preserving the deployed tag, `latest`, the newest `keep_count` tags, and any sub-manifests of kept tags.
- `get_orphaned_manifests(images, extra_repositories)` — finds `unknown@sha256:...` platform manifests no longer referenced by any tagged manifest list.
- `delete_ocir_images(cleanup_recommendations)` — deletes by OCID; 404s are treated as already-deleted. Returns `list[Image]` (returns `[]` when SDK unavailable — **not** `{}`).

Safety guards:
- Only OCIR images are considered (`image.is_ocir_image`).
- `latest` and the currently deployed tag are never deleted.
- Manifest-list sub-digests of kept tags are explicitly protected.
- Orphan detection skips a repo entirely if no manifest lists can be resolved (avoids deleting needed manifests when Docker auth fails).
- Deletion is opt-in via `OCIR_CLEANUP_ENABLED=true`.

### `src/discord_notifier.py`
Three public methods:
- `send_image_scan_report(complete_scan_result)`
- `send_cleanup_recommendations(cleanup)`
- `send_deletion_results(images, is_orphaned=False)`

**Library API**: this uses `dappertable` v1.1.x — `Column` / `Columns`, `DapperTable(columns=Columns([...]))`, `.render()`, `len(table)`. The older `DapperTableHeader` / `DapperTableHeaderOptions` / `.print()` / `.size` API is gone.

All values passed to `add_row` should be strings. Each paginated page is sent as a separate webhook POST with a 1-second sleep between requests to respect rate limits.

## Docker Image

Two-stage Dockerfile:
1. `trivy-builder` — `python:3.14-slim` + `curl` + `ca-certificates`, runs the official Trivy install script and drops the pinned `trivy` binary in `/usr/local/bin/`.
2. Final stage — `python:3.14-slim`, applies security upgrades, copies the trivy binary from the builder, installs Python deps via `pip install --no-cache-dir .`, copies `src/`, runs as non-root `scanner` (UID 1000).

The final image carries **no** `curl` / `wget` / `tar` / `git` / build toolchain. The Trivy DB is **not** pre-downloaded — `main()` fetches it on startup. Trivy version is pinned via `ARG TRIVY_VERSION` in the builder stage.

## CI/CD

The project uses **GitLab CI** (`.gitlab-ci.yml`), not GitHub Actions. Pipeline stages: bump-version, validate-docker, docker-push (multi-arch), trufflehog secret scanning, tox (pytest + pylint + bandit across Python 3.11–3.14), release-tag, MR/release notifications, renovate.

Pipeline templates are pulled in via the `include:` block at the top of `.gitlab-ci.yml`.

## Code Quality

Configuration lives in `pyproject.toml`:
- `[project.optional-dependencies].dev` — `bandit`, `pylint`, `pytest`, `pytest-cov`, `pytest-mock`, `pytest-asyncio`, `tox`.
- `[tool.pylint.*]` — pylint rules (max line length 120, etc.).

`tox.ini` defines envs `py311`..`py314` and exposes `pytest`, `pylint`, `bandit` as individual envs.

Running locally:

```bash
pip install -e ".[dev]"
tox              # full matrix
tox -e py313     # single python version
tox -e pytest    # pytest only
tox -e pylint    # pylint only
tox -e bandit    # bandit only
```

Current state: **100% line coverage**, pylint 10.00/10, bandit clean.

## Common Tasks

### Adding a new configuration option
1. Add the field to `Config` in `src/config.py`.
2. Add it to `from_env()` with `os.getenv()` (and a default).
3. Update `tests/conftest.py::base_config` so existing tests still pass — the fixture constructs `Config(...)` directly, so missing fields raise `TypeError`.
4. Update the env-var table in `README.md` and `DEVELOPMENT.md`.
5. If it gets stored as a secret, update `k8s/secret-example.yaml` and `k8s/cronjob.yaml`.

### Adding observability to a new module
1. `from logging import getLogger`
2. `logger = getLogger(__name__)` at module level.
3. Accept a `logger_provider` parameter in `__init__` (it may be `None`).
4. Add the OTLP log handler with a `None` check:
   ```python
   if logger_provider:
       logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))
   ```
5. **Don't add tracing spans** — tracing is intentionally not wired up.

### Adding a new metric
1. Add the gauge/counter creation to `create_metrics()` in `src/telemetry.py` and add it as a field on the `Metrics` dataclass.
2. Pass the `Metrics` instance to the module that needs it.
3. Always check for `None` before recording (`if self.metrics:`).
4. Document it in `README.md` if user-facing.

### Testing locally
1. Ensure `kubectl` can reach the target cluster.
2. Ensure `~/.oci/config` is set up if you intend to exercise OCIR paths.
3. Export any env vars you need (see DEVELOPMENT.md).
4. Run: `python -m src.main`.

## Common Pitfalls

1. **DO NOT** use `structlog` — stick to standard `logging.getLogger()`.
2. **DO NOT** add tracing back without confirming intent — it was deliberately removed (logs + metrics only).
3. **DO NOT** reintroduce `Image.version` / `ImageVersion` / semver comparison — they were removed along with the image-update check.
4. **DO NOT** forget to update `tests/conftest.py::base_config` when adding a `Config` field; the fixture constructs `Config(...)` directly, so missing fields raise `TypeError`.
5. **DO NOT** forget to check `if logger_provider:` / `if self.metrics:` before using them — both can be `None`.
6. **DO NOT** commit real secrets — use `k8s/secret-example.yaml` as the template.
7. **REMEMBER** OCIR deletion is destructive — keep `OCIR_CLEANUP_ENABLED=false` for any new repo until you've reviewed the dry-run recommendations.
8. **REMEMBER** the Trivy DB is downloaded at runtime, not baked into the image; the first scan in a fresh cache will be slower.
9. **REMEMBER** `dappertable` is v1.1.x — `Column` / `Columns` / `render()` / `len(table)`, not the older `DapperTableHeader` / `print()` / `.size` API.
10. **REMEMBER** when patching `src.registry_client.oci` in tests, `except oci.exceptions.ServiceError` resolves against the mock; set `mock_oci.exceptions.ServiceError = ServiceError` (the real class) if a test needs the except branch to actually catch.
