# Changelog

All notable changes to the OKE Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
