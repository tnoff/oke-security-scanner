"""Configuration for the secret-age tracker, loaded from env vars."""

import os
from dataclasses import dataclass


@dataclass
class SecretAgeConfig:
    """Tracker config; populated by `from_env`."""

    # Discord webhook — same value as the scanner's (security_scans_webhook).
    discord_webhook_url: str

    # Rotation thresholds. Defaults match docs/projects/secret-age-tracker.md.
    warn_days: int
    rotate_days: int

    # Layer-1 ledger ConfigMap (security-scanner ns) — name of the
    # ConfigMap whose data is `{tfvar_name: YYYY-MM-DD}`.
    layer1_configmap_name: str = "layer-1-rotation-ledger"
    layer1_configmap_namespace: str = "security-scanner"

    # OCI compartment to enumerate users in — tenancy root.
    # Sourced from the standard OCI config-file profile mounted at
    # ~/.oci/config (same as the scanner).
    oci_tenancy_ocid: str = ""

    # When false, skip the OCI reader (useful for local dev without OCI auth).
    enable_oci_reader: bool = True
    enable_k8s_reader: bool = True
    enable_layer1_reader: bool = True

    @classmethod
    def from_env(cls) -> "SecretAgeConfig":
        return cls(
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),
            warn_days=int(os.getenv("SECRET_AGE_WARN_DAYS", "90")),
            rotate_days=int(os.getenv("SECRET_AGE_ROTATE_DAYS", "180")),
            layer1_configmap_name=os.getenv("LAYER1_CONFIGMAP_NAME", "layer-1-rotation-ledger"),
            layer1_configmap_namespace=os.getenv("LAYER1_CONFIGMAP_NAMESPACE", "security-scanner"),
            oci_tenancy_ocid=os.getenv("OCI_TENANCY_OCID", ""),
            enable_oci_reader=os.getenv("ENABLE_OCI_READER", "true").lower() == "true",
            enable_k8s_reader=os.getenv("ENABLE_K8S_READER", "true").lower() == "true",
            enable_layer1_reader=os.getenv("ENABLE_LAYER1_READER", "true").lower() == "true",
        )
