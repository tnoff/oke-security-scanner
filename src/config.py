"""Configuration management for OKE Security Scanner."""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """Application configuration from environment variables."""

    # OTLP configuration
    otlp_endpoint: str
    otlp_insecure: bool
    otlp_metrics_enabled: bool
    otlp_logs_enabled: bool

    # Trivy configuration
    trivy_severity: str
    trivy_timeout: int
    trivy_platform: str

    # Scanning configuration
    namespaces: list[str]
    exclude_namespaces: list[str]

    # Discord webhook configuration (optional - enabled if URL provided)
    discord_webhook_url: str

    # OCIR cleanup configuration
    ocir_cleanup_enabled: bool
    ocir_cleanup_keep_count: int
    ocir_extra_repositories: list[str]

    # Phase toggles — the daily CronJob runs both; producer pipelines that
    # fire a one-off Job after pushing flip ENABLE_SCAN off so only the
    # cleanup pass runs (typically scoped via CLEANUP_REPO).
    enable_scan: bool
    enable_cleanup: bool
    # When set, the cleanup pass is scoped to this OCIR repo
    # (namespace-qualified, e.g. `tnoff/discord_bot`).
    cleanup_repo: str

    def __post_init__(self):
        if not self.enable_scan and not self.enable_cleanup:
            raise ValueError("At least one of ENABLE_SCAN / ENABLE_CLEANUP must be true")
        if self.cleanup_repo and not self.enable_cleanup:
            raise ValueError("CLEANUP_REPO is set but ENABLE_CLEANUP=false — nothing will use it")

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            # OTLP configuration
            otlp_endpoint=os.getenv("OTLP_ENDPOINT", "http://localhost:4317"),
            otlp_insecure=os.getenv("OTLP_INSECURE", "true").lower() == "true",
            otlp_metrics_enabled=os.getenv("OTLP_METRICS_ENABLED", "false").lower() == "true",
            otlp_logs_enabled=os.getenv("OTLP_LOGS_ENABLED", "false").lower() == "true",

            # Trivy configuration
            trivy_severity=os.getenv("TRIVY_SEVERITY", "CRITICAL,HIGH"),
            trivy_timeout=int(os.getenv("TRIVY_TIMEOUT", "300")),
            trivy_platform=os.getenv("TRIVY_PLATFORM", ""),

            # Scanning configuration
            namespaces=os.getenv("SCAN_NAMESPACES", "").split(",") if os.getenv("SCAN_NAMESPACES") else [],
            exclude_namespaces=os.getenv("EXCLUDE_NAMESPACES", "kube-system,kube-public,kube-node-lease").split(","),

            # Discord webhook configuration (optional - enabled if URL provided)
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),

            # OCIR cleanup configuration
            ocir_cleanup_enabled=os.getenv("OCIR_CLEANUP_ENABLED", "false").lower() == "true",
            ocir_cleanup_keep_count=int(os.getenv("OCIR_CLEANUP_KEEP_COUNT", "5")),
            # Comma separated list of extra repos (filter empties so unset → [])
            ocir_extra_repositories=[r for r in os.getenv('OCIR_EXTRA_REPOSITORIES', "").split(',') if r],

            # Phase toggles (default both on — daily CronJob behavior)
            enable_scan=os.getenv("ENABLE_SCAN", "true").lower() == "true",
            enable_cleanup=os.getenv("ENABLE_CLEANUP", "true").lower() == "true",
            cleanup_repo=os.getenv("CLEANUP_REPO", ""),
        )
