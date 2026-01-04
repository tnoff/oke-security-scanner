# Changelog

All notable changes to the OKE Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.6] - 2026-01-04

### Fixed
- **OCIR repository name normalization**
  - Fixed OCIR image repository lookups by stripping namespace prefix from repository names
  - OCIR API expects repository names without namespace (e.g., `discord_bot` not `namespace/discord_bot`)
  - Added `normalize_ocir_repository()` method to handle namespace stripping
  - Updates `_find_repository_compartment()` and `_get_ocir_images_via_sdk()` to use normalized names
- **Timezone-aware datetime handling**
  - Fixed `TypeError` when comparing timezone-aware datetimes from OCI SDK with timezone-naive datetimes
  - Updated `age_days()` method to use `datetime.now(timezone.utc)` for proper comparisons
  - Prevents crashes when calculating image age for OCIR images
- **Mixed version type comparison**
  - Fixed version comparison when repositories contain both semver tags and commit hash tags
  - Updated `get_latest_version()` to populate creation dates for all version types
  - When both semver and non-semver versions exist, compares by creation date to find truly latest
  - Resolves issue where semver versions were incorrectly chosen over newer commit hash versions

### Added
- **Alternate tag display for better commit hash workflows**
  - When current image uses commit hash and latest is semver, displays corresponding commit hash if available
  - New `_find_alternate_tag()` method finds non-semver tags with matching creation timestamps
  - Version reports show: `Latest: abc1234 (version 0.2.1)` instead of just `Latest: 0.2.1`
  - Helps teams using commit-hash-based deployments identify which commit to deploy
- **Comprehensive test coverage for OCIR fixes**
  - 10 new tests covering repository normalization, timezone handling, and alternate tag display
  - Tests for mixed version comparison scenarios
  - New test suite for `version_reporter.py` module (7 tests)
  - Code coverage improved from 66% to 74%
  - `version_reporter.py` coverage: 11% → 90%

### Changed
- Enhanced `check_for_updates()` to include `alternate_tag` in update info
- Updated version report formatting to handle all version type combinations:
  - Both semver
  - Both non-semver
  - Non-semver → semver (with/without alternate tag)
  - Semver → non-semver

## [0.0.5] - 2025-12-31

### Added
- **Image version update detection across multiple registries**
  - Automatically checks for newer versions of deployed images
  - Supports semver tags (v1.2.3, 1.2.3) with proper version comparison
  - Supports commit hash tags compared by image creation date
  - Multi-registry support: OCIR, Docker Hub, GitHub Container Registry
  - Categorizes updates as MAJOR (breaking changes) vs minor/patch (safe updates)
- New `src/registry_client.py` module for registry API interactions
  - Fetches available tags from registry APIs
  - Retrieves image manifests and creation dates
  - Parses and compares semver and commit hash versions
  - Supports authenticated OCIR access and public Docker Hub/ghcr.io access
- New `src/version_reporter.py` module for version update reporting
  - Generates formatted console reports with MAJOR and minor/patch sections
  - Shows version differences and image age for outdated deployments
- **Enhanced Discord notifications with two-message block system**
  - Block 1: Vulnerability scan results (summary + CRITICAL CVEs table + CSV)
  - Block 2: Version update results (summary + minor/patch updates table)
  - MAJOR updates excluded from Discord message (available in CSV only)
  - Version updates shown with type indicators (MAJOR/Minor/Patch/Commit Hash)
- **Comprehensive CSV reporting with two sections**
  - Section 1: Vulnerabilities (Image, CVE, Severity, Fixed Version)
  - Section 2: Version Updates (Image, Current Version, Latest Version, Update Type, Age, Version Diff)
  - Both sections included in single CSV attachment for complete audit trail

### Changed
- Updated Discord notification format to use two separate message blocks
  - First block focuses on security vulnerabilities
  - Second block focuses on version updates
  - Improved clarity and reduced information overload
- Enhanced `send_scan_report()` to accept `update_results` parameter
- Added `_build_update_table()` method for formatting version update tables
- Updated `_generate_csv()` to include version update data in separate section
- Updated main scan workflow to include version checking step
- Updated architecture diagram to show version checking as step 4

### Documentation
- Updated README.md with version tracking features and multi-registry support
- Added version update example outputs to Discord notifications section
- Updated AGENTS.md with complete registry_client.py and version_reporter.py documentation
- Added "Version Update Checking Implementation Details" section to AGENTS.md
  - Registry API patterns and authentication methods
  - Version comparison logic for semver and commit hash tags
  - Performance considerations and optimization strategies
  - Error handling scenarios

## [0.0.4] - 2025-12-30

### Changed
- **Discord webhook notifications now use CSV file attachments**
  - Sends a single message instead of multiple paginated messages to reduce channel spam
  - Critical vulnerabilities **with available fixes** are displayed in the channel for immediate visibility
  - Full vulnerability report attached as downloadable CSV file
  - CSV includes all vulnerabilities (CRITICAL, HIGH, MEDIUM, LOW) sorted by severity
  - CSV format: Image, CVE, Severity, Fixed Version
- Enhanced `_build_vulnerability_table()` with `only_with_fixes` parameter to filter vulnerabilities
- Updated `_send_message()` to support multipart/form-data file uploads

### Added
- New `_generate_csv()` method in `DiscordNotifier` for comprehensive vulnerability reporting
- CSV attachment support via Discord webhook file uploads
- Improved test coverage for Discord notifications:
  - Test for CSV file attachment functionality
  - Test for `only_with_fixes` filter behavior
  - Test for CSV generation and severity-based sorting

## [0.0.3] - 2025-12-26

### Added
- Discord webhook integration for scan result notifications
  - Sends formatted scan reports with vulnerability counts and image details
  - Displays top 10 vulnerable images in a paginated table format
  - Optional configuration via `DISCORD_WEBHOOK_URL` environment variable
  - Non-blocking: webhook failures don't fail the scan
- HIGH severity logging alongside CRITICAL vulnerabilities

### Changed
- Updated DapperTable library usage with new header API
  - Migrated to `DapperTableHeaderOptions` and `DapperTableHeader` for improved table formatting
  - Enhanced Discord notification table presentation
- Improved logging to include both CRITICAL and HIGH severity findings

## [0.0.2] - 2025-12-25

### Fixed
- Fixed Python logging to use f-strings instead of kwargs for standard logger compatibility
  - Updated all logging calls across `scanner.py`, `k8s_client.py`, and `main.py`
  - Resolves `TypeError: Logger._log() got an unexpected keyword argument` errors
- Fixed OCIR authentication for private images
  - Corrected username format to `{namespace}/{username}` as required by OCIR
  - Private images now authenticate successfully
- Fixed OTLP endpoint configuration
  - Changed from port 4317 (gRPC) to port 4318 (HTTP) to match HTTP exporters
  - Resolves connection reset errors when exporting telemetry
  - Simplified environment variables to use `OTEL_EXPORTER_OTLP_PROTOCOL`
- Fixed telemetry shutdown for short-lived CronJobs
  - Added `force_flush()` calls before shutdown to ensure all telemetry is exported
  - Prevents data loss when job completes quickly

### Added
- Comprehensive progress logging throughout the scan workflow
  - Startup banner and configuration details
  - Per-image scan progress indicators ([1/N], [2/N], etc.)
  - Success (✓), warning (⚠), and error (✗) indicators
  - Detailed summary table at completion
- Set default log level to DEBUG for better troubleshooting
- Configured logs to output to stdout for Kubernetes log collection
- Added `otel.access: enabled` label to pod template for network policy compatibility

### Changed
- Renamed `metrics` variable to `scanner_metrics` to avoid shadowing imported module
- Improved log message clarity with structured output and visual separators

## [0.0.1] - 2025-12-20

### Added
- Initial release of OKE Security Scanner
- Trivy-based vulnerability scanning for Kubernetes cluster images
- OpenTelemetry integration for traces, metrics, and logs
- OCIR private registry support
- Configurable namespace scanning with exclusions
- CronJob deployment for scheduled scans
