"""Configuration management for OKE Security Scanner."""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """Application configuration from environment variables."""

    # OTLP configuration
    otlp_endpoint: str
    otlp_insecure: bool
    otlp_traces_enabled: bool
    otlp_metrics_enabled: bool
    otlp_logs_enabled: bool

    # Trivy configuration
    trivy_severity: str
    trivy_timeout: int

    # Scanning configuration
    namespaces: list[str]
    exclude_namespaces: list[str]

    # Discord webhook configuration (optional - enabled if URL provided)
    discord_webhook_url: str

    # OCIR cleanup configuration
    ocir_cleanup_enabled: bool
    ocir_cleanup_keep_count: int
    ocir_extra_repositories: list[str]

    # OKE node image check configuration
    oke_image_check_enabled: bool
    oke_cluster_ocid: str

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            # OTLP configuration
            otlp_endpoint=os.getenv("OTLP_ENDPOINT", "http://localhost:4317"),
            otlp_insecure=os.getenv("OTLP_INSECURE", "true").lower() == "true",
            otlp_traces_enabled=os.getenv("OTLP_TRACES_ENABLED", "false").lower() == "true",
            otlp_metrics_enabled=os.getenv("OTLP_METRICS_ENABLED", "false").lower() == "true",
            otlp_logs_enabled=os.getenv("OTLP_LOGS_ENABLED", "false").lower() == "true",

            # Trivy configuration
            trivy_severity=os.getenv("TRIVY_SEVERITY", "CRITICAL,HIGH"),
            trivy_timeout=int(os.getenv("TRIVY_TIMEOUT", "300")),

            # Scanning configuration
            namespaces=os.getenv("SCAN_NAMESPACES", "").split(",") if os.getenv("SCAN_NAMESPACES") else [],
            exclude_namespaces=os.getenv("EXCLUDE_NAMESPACES", "kube-system,kube-public,kube-node-lease").split(","),

            # Discord webhook configuration (optional - enabled if URL provided)
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),

            # OCIR cleanup configuration
            ocir_cleanup_enabled=os.getenv("OCIR_CLEANUP_ENABLED", "false").lower() == "true",
            ocir_cleanup_keep_count=int(os.getenv("OCIR_CLEANUP_KEEP_COUNT", "5")),
            # Comma separated list of extra repos
            ocir_extra_repositories=os.getenv('OCIR_EXTRA_REPOSITORIES', "").split(','),

            # OKE node image check configuration
            oke_image_check_enabled=os.getenv("OKE_IMAGE_CHECK_ENABLED", "false").lower() == "true",
            oke_cluster_ocid=os.getenv("OKE_CLUSTER_OCID", ""),
        )
