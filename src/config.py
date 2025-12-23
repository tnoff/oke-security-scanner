"""Configuration management for OKE Security Scanner."""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """Application configuration from environment variables."""

    # OCIR credentials (same as github-workflows/ocir-push.yml)
    oci_registry: str
    oci_username: str
    oci_token: str
    oci_namespace: str

    # OTLP configuration
    otlp_endpoint: str
    otlp_insecure: bool

    # Trivy configuration
    trivy_severity: str
    trivy_timeout: int

    # Scanning configuration
    namespaces: list[str]
    exclude_namespaces: list[str]

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            # OCIR credentials
            oci_registry=os.getenv("OCI_REGISTRY", ""),
            oci_username=os.getenv("OCI_USERNAME", ""),
            oci_token=os.getenv("OCI_TOKEN", ""),
            oci_namespace=os.getenv("OCI_NAMESPACE", ""),

            # OTLP configuration
            otlp_endpoint=os.getenv("OTLP_ENDPOINT", "http://localhost:4317"),
            otlp_insecure=os.getenv("OTLP_INSECURE", "true").lower() == "true",

            # Trivy configuration
            trivy_severity=os.getenv("TRIVY_SEVERITY", "CRITICAL,HIGH"),
            trivy_timeout=int(os.getenv("TRIVY_TIMEOUT", "300")),

            # Scanning configuration
            namespaces=os.getenv("SCAN_NAMESPACES", "").split(",") if os.getenv("SCAN_NAMESPACES") else [],
            exclude_namespaces=os.getenv("EXCLUDE_NAMESPACES", "kube-system,kube-public,kube-node-lease").split(","),
        )

    def validate(self) -> None:
        """Validate required configuration."""
        required = {
            "OCI_REGISTRY": self.oci_registry,
            "OCI_USERNAME": self.oci_username,
            "OCI_TOKEN": self.oci_token,
            "OCI_NAMESPACE": self.oci_namespace,
        }

        missing = [key for key, value in required.items() if not value]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
