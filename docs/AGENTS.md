# AI Agent Context for OKE Utilities

Context for AI agents (Claude, GPT, etc.) working on this codebase.

For **what the project does**, **how to install/run it**, **env-var reference**, **authentication setup**, and the **Kubernetes deployment shape**, read [README.md](../README.md). For **local-dev setup** and the **DEV env-var reference**, read [DEVELOPMENT.md](./DEVELOPMENT.md). This file covers only the things an agent needs that aren't in those docs.

## File Structure

```
oke-utilities/
├── packages/             # Four separate installable packages/images -- see
│   │                     # docs/projects/oke-security-scanner-package-split.md.
│   │                     # None carries its own dev-tool versions or pylint
│   │                     # config; root pyproject.toml is the single source
│   │                     # for both (see Code Quality below).
│   ├── core/             # oke-scanner-core: shared by scan/secret_age/ocir_cleanup.
│   │   └── src/oke_scanner_core/
│   │       ├── k8s_auth.py        # load_k8s_config(): incluster, falls back to kubeconfig
│   │       ├── image.py           # Image dataclass
│   │       ├── k8s_client.py      # KubernetesClient: image discovery
│   │       └── telemetry.py       # setup_telemetry/shutdown_telemetry. Behind the
│   │                               # `oke-scanner-core[telemetry]` extra -- secret_age
│   │                               # depends on bare oke-scanner-core and never installs
│   │                               # the OTel SDK; scan and cleanup both request the extra.
│   ├── scan/             # oke-scan: own package, own Dockerfile, own
│   │   │                 # CronJob + entry point (`python -m scan`). Discovers all
│   │   │                 # images deployed in OKE and scans each with Trivy.
│   │   ├── Dockerfile
│   │   ├── pyproject.toml
│   │   ├── src/scan/
│   │   │   ├── main.py, __main__.py, config.py, scanner.py, discord_notifier.py
│   │   │   └── telemetry.py  # the image_scan gauge only; setup/shutdown re-exported
│   │   │                     # from oke_scanner_core.telemetry, not defined here
│   │   └── tests/
│   ├── secret_age/       # secret-age-tracker: own package, own Dockerfile, own
│   │   │                 # CronJob + entry point (`python -m secret_age`).
│   │   │                 # No Trivy, no OCIR cleanup code, no OpenTelemetry.
│   │   ├── Dockerfile
│   │   ├── pyproject.toml
│   │   ├── src/secret_age/
│   │   │   ├── main.py, __main__.py, config.py, aggregator.py, finding.py, discord_report.py
│   │   │   └── readers/  # k8s.py, layer1_ledger.py, oci_iam.py -- one per secret source
│   │   └── tests/
│   └── ocir_cleanup/     # ocir-cleanup: own package, own Dockerfile, own CronJob +
│       │                 # entry point (`python -m ocir_cleanup`). No Trivy binary at all;
│       │                 # does use OpenTelemetry (unlike secret_age -- OTLP_METRICS_ENABLED
│       │                 # and OTLP_LOGS_ENABLED are both genuinely on in
│       │                 # ocir-cleanup-cronjob.yaml, the docker-apps CronJob's own name --
│       │                 # renamed from cleanup-all, see docker-apps' rename PR).
│       ├── Dockerfile
│       ├── pyproject.toml
│       ├── src/ocir_cleanup/
│       │   ├── main.py, __main__.py, config.py, registry_client.py, discord_notifier.py
│       └── tests/
├── k8s/                  # CronJob + RBAC + Secret examples
├── .github/workflows/    # GitHub Actions: ci.yml, release.yml, scheduled.yml
├── pyproject.toml        # No importable code of its own -- see Code Quality below.
│                         # Just the dev-tool versions tox installs and the
│                         # pylint config tox's combined lint invocation reads
│                         # from repo-root cwd, plus VERSION's dynamic-version
│                         # wiring (unused by anything else; tag.yml/
│                         # bump-version.yml read VERSION directly as text).
├── tox.ini               # pytest / pylint / bandit envs -- covers all four
│                         # packages/*/src, see its own header comment
├── VERSION               # Semantic version for the whole repo's release stream
│                         # (tag.yml/bump-version.yml), independent of each
│                         # package's own pyproject.toml version field
├── README.md             # User-facing documentation
├── mkdocs.yml            # Backstage TechDocs site config
└── docs/
    ├── README.md         # Symlink to ../README.md (single copy for GitHub + TechDocs)
    ├── DEVELOPMENT.md    # Local-dev setup
    ├── AGENTS.md         # This file
    └── CONTRIBUTING.md   # Canonical-remote statement
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

### `packages/core/src/oke_scanner_core/telemetry.py`
`setup_telemetry(cfg) -> tuple[Optional[MeterProvider], Optional[LoggerProvider]]`. `cfg` just needs `otlp_metrics_enabled`/`otlp_logs_enabled` attributes -- any package's own Config dataclass satisfies this structurally. Each provider is `None` if that OTLP component is disabled. Resource attributes come from `OTELResourceDetector()`. `shutdown_telemetry(meter_provider, logger_provider, logger=None)` flushes and shuts down whichever providers are non-`None`; duck-typed on `.force_flush()`/`.shutdown()`, called from each package's own `main()` `finally:` block.

Gated behind the `oke-scanner-core[telemetry]` extra (see File Structure above) -- don't add a new import here without checking it doesn't leak the OTel SDK into secret_age's dependency set.

### `packages/scan/src/scan/telemetry.py`
Scan-only now: `create_metrics(meter_provider)` builds the `image_scan` gauge (returns `None` when its argument is `None`); `Metrics` is the dataclass wrapping it. Re-exports `setup_telemetry`/`shutdown_telemetry` from `oke_scanner_core.telemetry` so `main.py`'s existing `from .telemetry import ...` line didn't need to change.

### `packages/scan/src/scan/main.py`
Orchestration only, scan phase alone as of the package split (no `ENABLE_SCAN`/`ENABLE_CLEANUP` toggles or `run_cleanup` anymore -- see `packages/ocir_cleanup/src/ocir_cleanup/main.py` for that):

- `run_scan(config, logger_provider, scanner_metrics, notifier) -> set[Image]` — updates the Trivy DB, lists pods via `oke_scanner_core.k8s_client.KubernetesClient`, scans every discovered image, posts the Discord report, emits metrics.

The `if __name__ == "__main__":` guard is marked `# pragma: no cover` (standard untestable pattern). A separate `__main__.py` also does `sys.exit(main())` so `python -m scan` works -- `main()` itself still returns `None`, matching its pre-split behavior (an unhandled exception exits non-zero either way; nothing here signals failure via an explicit return code).

### `packages/scan/src/scan/scanner.py`
- `update_database()` — runs `trivy image --download-db-only` once at startup; logs and continues on timeout/error.
- `scan_image(image)` — invokes Trivy with JSON output, parses CVE results into `ScanResult`.
- `_cleanup_image_cache()` — removes `fanal/` from the Trivy cache after each scan to bound disk usage; the vulnerability DB is preserved.

### `packages/core/src/oke_scanner_core/k8s_client.py`
- `KubernetesClient(namespaces, exclude_namespaces, logger_provider=None)` — takes the two discovery-scope lists directly, not a `Config` object, so it doesn't depend on any package's own Config shape.
- Calls `oke_scanner_core.k8s_auth.load_k8s_config()` for the incluster/kubeconfig-fallback bootstrap (see below) rather than inlining it.
- `get_all_images()` enumerates namespaces (configured set or all-minus-exclusions), then collects images from regular + init containers across all pods.
- Still carries the `kubernetes==36.0.0` bearer-token mirror workaround (`api_key['authorization']` → `api_key['BearerToken']`) — a no-op once upstream's naming agrees, so it's safe to leave even if the bug gets fixed.

### `packages/core/src/oke_scanner_core/image.py`
The `Image` dataclass: parses `registry / repo_name / tag`, strips digest suffixes (`@sha256:...`), and exposes `is_ocir_image`. There is **no** `Image.version` / semver comparison anymore — don't reintroduce it.

### `packages/core/src/oke_scanner_core/k8s_auth.py`
`load_k8s_config()` — tries `load_incluster_config()` first, falls back to `load_kube_config()` for local dev. Used by `KubernetesClient` above, and directly by `secret_age`'s own k8s/layer1_ledger readers (which don't use `KubernetesClient` at all).

### `packages/core/src/oke_scanner_core/discord_webhook.py`
`DiscordWebhookClient(webhook_url)` — `send_message(content_list)` and `send_file(message_content, file_contents, file_name)`. Just the low-level webhook mechanics; report-shape formatting (which table columns, which result type) stays in the package that owns that report (`packages/scan/src/scan/discord_notifier.py`'s `send_image_scan_report`, `packages/ocir_cleanup/src/ocir_cleanup/discord_notifier.py`'s `send_cleanup_recommendations`/`send_deletion_results`). Each of those wraps a `DiscordWebhookClient` internally rather than importing `requests` directly.

### `packages/ocir_cleanup/src/ocir_cleanup/registry_client.py`
OCIR-only. There is no Docker Hub / ghcr.io version-check logic anymore. Moved verbatim out of what was then the root `src/registry_client.py` -- `oci` is no longer a scan dependency at all, which is most of why the scan image dropped from 810.8 MB to ~393 MB at the time of that split (measured; also dropped the `build-essential` stage entirely, since `crc32c` -- `oci`'s transitive dep that needed compiling -- left with it).

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
- `get_image_creation_date(image) -> Optional[datetime]` — public, but not called anywhere in `packages/ocir_cleanup/src/`; only `packages/ocir_cleanup/tests/test_registry_client.py` exercises it. Don't assume something calls this in production.

Safety guards:
- Only OCIR images are considered (`image.is_ocir_image`).
- `latest` and the currently deployed tag are never deleted.
- Manifest-list sub-digests of kept tags are explicitly protected.
- Orphan detection skips a repo entirely if no manifest lists can be resolved (avoids deleting needed manifests when Docker auth fails).
- Deletion is opt-in via `OCIR_CLEANUP_ENABLED=true`.

### `packages/ocir_cleanup/src/ocir_cleanup/main.py`
`run_cleanup(config, logger_provider, notifier)` — no `discovered_images` parameter (dropped along with the split: no deployed CronJob ever ran scan+cleanup combined in one process, so there was nothing live to preserve by keeping the hand-off). Always lists pods itself via `KubernetesClient`. If `CLEANUP_REPO` is set, the run is scoped to that single OCIR repo (image set filtered + `extra_repositories=[cleanup_repo]` so cleanup happens even with nothing deployed); otherwise it sweeps every image and uses `config.ocir_extra_repositories`.

Producer pipelines fire a one-off Job with `CLEANUP_REPO=<repo>` so cleanup runs right after a push, without waiting for the daily cron. The deployed-tag protection still works: at push time the cluster is still running the old tag, so `get_old_ocir_images` finds it via k8s discovery and protects it.

`main()` returns an `int` (0/1) rather than calling `sys.exit()` directly -- `__main__.py` does `sys.exit(main())`. This is a deliberate small deviation from scan's `main()`, which still returns `None` (see above) because `Config.from_env()`, unlike `CleanupConfig.from_env()`, never had anything to validate either -- there was nothing to gain by adding an int return there.

### `packages/scan/src/scan/discord_notifier.py` / `packages/ocir_cleanup/src/ocir_cleanup/discord_notifier.py`
Each package keeps only the report-shape method(s) it needs, both wrapping `oke_scanner_core.discord_webhook.DiscordWebhookClient`:
- `packages/scan/src/scan/discord_notifier.py`: `send_image_scan_report(complete_scan_result)`
- `packages/ocir_cleanup/src/ocir_cleanup/discord_notifier.py`: `send_cleanup_recommendations(cleanup)`, `send_deletion_results(images, scanned_repos=None, is_orphaned=False)` — `scanned_repos` drives the "No `<repo>` ... deleted" reporting for clean repos

**Library API**: both use `dappertable` v1.1.x — `Column` / `Columns`, `DapperTable(columns=Columns([...]))`, `.render()`, `len(table)`. The older `DapperTableHeader` / `DapperTableHeaderOptions` / `.print()` / `.size` API is gone.

All values passed to `add_row` should be strings. Each paginated page is sent as a separate webhook POST with a 1-second sleep between requests to respect rate limits (in `DiscordWebhookClient`, not per-package).

## Docker Image

Four packages, four `Dockerfile`s, all under `packages/*/Dockerfile` now
(scan's used to live at repo root; moved into `packages/scan/Dockerfile` to
match the other three -- see
docs/projects/oke-security-scanner-package-split.md). Only `packages/scan/
Dockerfile` has a Trivy stage; `packages/secret_age`'s also has no
OpenTelemetry deps (`packages/ocir_cleanup`'s does -- `ocir-cleanup-cronjob.yaml`
genuinely enables OTLP metrics+logs). This section covers
`packages/scan/Dockerfile`.

All four build from repo-root context (so each can also `COPY packages/
core`), even though the Dockerfile itself lives under `packages/<name>/`.

Two-stage Dockerfile (the `build-essential` compile stage is gone -- it only
existed for `oci`'s `crc32c` transitive dep, and `oci` left with
`packages/ocir_cleanup`):
1. `trivy-builder` — `python:3.14-slim` + `curl` + `ca-certificates`, runs the official Trivy install script and drops the pinned `trivy` binary in `/usr/local/bin/`.
2. `py-builder` — plain `python:3.14-slim`, runs `pip install --no-cache-dir --prefix=/install ./packages/core ./packages/scan` (both packages properly pip-installed -- no loose-copy fallback the way root `src/` once needed, since `scan` didn't have a real top-level import name until this move).
3. Final stage — `python:3.14-slim`, applies security upgrades, copies the `trivy` binary from `trivy-builder` and the installed packages from `py-builder`'s `/install` (`COPY --from=py-builder /install /usr/local`, no `pip install` and no loose source `COPY` in the final stage at all now -- `scan` is a real installed package), runs as non-root `scanner` (UID 1000).

The final image carries **no** `curl` / `wget` / `tar` / `git` / build toolchain. The Trivy DB is **not** pre-downloaded — `main()` fetches it on startup. Trivy version is pinned via `ARG TRIVY_VERSION` in the builder stage.

Measured (not read off the Dockerfile), at the time of the original scan/cleanup split: **810.8 MB → 393.4 MB** for this image; `packages/secret_age`'s own is 630.5 MB; `packages/ocir_cleanup`'s own is 658.0 MB. Re-measured after moving `src/` into `packages/scan/` (same day, same floating deps, A/B against the pre-move Dockerfile): 412 MB before → 413 MB after -- confirms the move itself is size-neutral; the drift from the 393.4 MB figure above is unpinned transitive deps resolving differently over time, not this restructuring.

## CI/CD

The project uses **GitHub Actions**. `.github/workflows/` holds three callers:

- `ci.yml` — on pull requests: trufflehog secret scan, the tox matrix (pytest + pylint + bandit across Python 3.11–3.14) with a diff-cover gate, a conditional image build + image scan for EACH image (`changes` job outputs `image`/`secret_age_image`/`ocir_cleanup_image`, gated on separate path filters -- not a matrix, so each has its own `needs`/`if`; `packages/core/*` flips all three, since all three depend on it), `bump-version`, and `check-workflow-contracts` (catches a `uses:` whose inputs/secrets no longer match the pinned callee). The scan build/scan job passes `dockerfile: packages/scan/Dockerfile` explicitly now (the reusable `docker-build-check.yml`'s default is root `Dockerfile`, which no longer exists).
- `release.yml` — on `main`: fold the changelog, tag from `VERSION` (shared across all three images), push each changed image to OCIR under its own OCIR repo name, and trigger a `docker-apps` pin bump per image (`oke-scan`, `secret-age-tracker` and `ocir-cleanup` are separate `bump_source`s, each its own explicit `push-image-*`/`trigger-bump-*` job pair -- not a matrix; matrix job outputs aren't addressable per-leg, and `trigger-bump` needs the exact tag its own paired push produced). Same `dockerfile: packages/scan/Dockerfile` override on the scan `push-image` job as `ci.yml`. Scan's `repo_name` is now hardcoded `oke-scan` directly in the job (matching secret-age-tracker/ocir-cleanup's own jobs) rather than sourced from a terraform-set `vars.OCI_REPO_NAME` -- that variable only ever pointed at one of the three images and was dropped once there was no single "the" image left to name it after.
- `scheduled.yml` — weekly: Renovate and branch cleanup.

Each job calls a reusable workflow from `tnoff/github-workflows`, SHA-pinned in `uses:` and kept current by Renovate's github-actions manager. There is no `.gitlab-ci.yml` in this repo -- `ci.yml`'s own header notes it was ported from one, but the file itself isn't present, frozen or otherwise.

## Code Quality

Configuration lives in root `pyproject.toml` -- which has no importable code
of its own (see File Structure above), but is the single source both tox
and pylint actually use:
- `[project.optional-dependencies].dev` — `bandit`, `pylint`, `pytest`, `pytest-cov`, `pytest-mock`, `pytest-asyncio`, `tox`, `coverage`. tox's `extras = dev` installs these for every testenv; no package's own pyproject.toml carries a competing copy.
- `[tool.pylint.*]` — pylint rules (max line length 120, etc.). tox's combined `pylint packages/core/src packages/scan/src ...` invocation runs from repo-root cwd, and pylint discovers config from CWD -- so this is the block actually in effect for all four packages. None of the four packages' own `pyproject.toml` carries a `[tool.pylint.*]` block (two used to, found to be dead weight and removed when `packages/scan` joined them -- don't re-add one without checking it would actually be read).

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
1. Add the field to the relevant Config -- `Config` in `packages/scan/src/scan/config.py` (scan), `CleanupConfig` in `packages/ocir_cleanup/src/ocir_cleanup/config.py`, or `SecretAgeConfig` in `packages/secret_age/src/secret_age/config.py`. These no longer share fields; adding a scan-only option doesn't touch the other two.
2. Add it to `from_env()` with `os.getenv()` (and a default).
3. Update that package's own `tests/conftest.py::base_config` fixture so existing tests still pass — it constructs the Config dataclass directly, so a missing field raises `TypeError`.
4. Update the env-var table in `README.md` and `DEVELOPMENT.md`.
5. If it gets stored as a secret, update `k8s/secret-example.yaml` and the relevant CronJob manifest in `docker-apps`.

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
1. Add the gauge/counter creation to `create_metrics()` in `packages/scan/src/scan/telemetry.py` and add it as a field on the `Metrics` dataclass. (Scan-only concept -- `packages/ocir_cleanup` has no metrics instrument of its own today.)
2. Pass the `Metrics` instance to the module that needs it.
3. Always check for `None` before recording (`if self.metrics:`).
4. Document it in `README.md` if user-facing.

### Testing locally
1. Ensure `kubectl` can reach the target cluster.
2. Ensure `~/.oci/config` is set up if you intend to exercise OCIR paths (only relevant for `packages/ocir_cleanup` and `packages/secret_age` -- scan no longer touches OCI at all).
3. Export any env vars you need (see DEVELOPMENT.md).
4. Run: `python -m scan`, `python -m ocir_cleanup`, or `python -m secret_age`.

## Common Pitfalls

1. **DO NOT** use `structlog` — stick to standard `logging.getLogger()`.
2. **DO NOT** add tracing back without confirming intent — it was deliberately removed (logs + metrics only).
3. **DO NOT** reintroduce `Image.version` / `ImageVersion` / semver comparison — they were removed along with the image-update check.
4. **DO NOT** forget to update `packages/scan/tests/conftest.py::base_config` or `packages/ocir_cleanup/tests/conftest.py::base_config` when adding a field to the respective Config; each fixture constructs its dataclass directly, so a missing field raises `TypeError`.
5. **DO NOT** forget to check `if logger_provider:` / `if self.metrics:` before using them — both can be `None`.
6. **DO NOT** commit real secrets — use `k8s/secret-example.yaml` as the template.
7. **DO NOT** add a new unconditional import to `oke_scanner_core.telemetry` (or any other core module) without checking whether it belongs behind an extra — that module is the one place a careless addition would leak the OpenTelemetry SDK into `secret_age`'s image.
8. **REMEMBER** OCIR deletion is destructive — keep `OCIR_CLEANUP_ENABLED=false` for any new repo until you've reviewed the dry-run recommendations.
9. **REMEMBER** the Trivy DB is downloaded at runtime, not baked into the image; the first scan in a fresh cache will be slower.
10. **REMEMBER** `dappertable` is v1.1.x — `Column` / `Columns` / `render()` / `len(table)`, not the older `DapperTableHeader` / `print()` / `.size` API.
11. **REMEMBER** when patching `cleanup.registry_client.oci` in tests, `except oci.exceptions.ServiceError` resolves against the mock; set `mock_oci.exceptions.ServiceError = ServiceError` (the real class) if a test needs the except branch to actually catch.
