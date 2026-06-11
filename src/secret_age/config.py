"""Configuration for the secret-age tracker, loaded from env vars."""

import os
from dataclasses import dataclass, field


@dataclass
class SecretAgeConfig:
    """Tracker config; populated by `from_env`."""

    # Discord webhook — same value as the scanner's (security_scans_webhook).
    discord_webhook_url: str

    # Rotation thresholds. Defaults match docs/projects/secret-age-tracker.md.
    warn_days: int
    rotate_days: int

    # GitLab — for blaming SealedSecret YAMLs in docker-apps and listing
    # PAT expiries.
    gitlab_url: str
    gitlab_token: str
    # Path-glob list of SealedSecret-bearing files to blame, relative
    # to the docker-apps repo root.
    docker_apps_project: str
    sealed_secret_paths: list[str] = field(default_factory=list)

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
    enable_gitlab_reader: bool = True
    enable_k8s_reader: bool = True
    enable_layer1_reader: bool = True

    @classmethod
    def from_env(cls) -> "SecretAgeConfig":
        return cls(
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),
            warn_days=int(os.getenv("SECRET_AGE_WARN_DAYS", "90")),
            rotate_days=int(os.getenv("SECRET_AGE_ROTATE_DAYS", "180")),
            gitlab_url=os.getenv("GITLAB_URL", "https://gitlab.com"),
            gitlab_token=os.getenv("GITLAB_TOKEN", ""),
            docker_apps_project=os.getenv("DOCKER_APPS_PROJECT", "tnoff-projects/docker-apps"),
            sealed_secret_paths=[
                p for p in os.getenv("SEALED_SECRET_PATHS", ",".join(_DEFAULT_SEALED_PATHS)).split(",") if p
            ],
            layer1_configmap_name=os.getenv("LAYER1_CONFIGMAP_NAME", "layer-1-rotation-ledger"),
            layer1_configmap_namespace=os.getenv("LAYER1_CONFIGMAP_NAMESPACE", "security-scanner"),
            oci_tenancy_ocid=os.getenv("OCI_TENANCY_OCID", ""),
            enable_oci_reader=os.getenv("ENABLE_OCI_READER", "true").lower() == "true",
            enable_gitlab_reader=os.getenv("ENABLE_GITLAB_READER", "true").lower() == "true",
            enable_k8s_reader=os.getenv("ENABLE_K8S_READER", "true").lower() == "true",
            enable_layer1_reader=os.getenv("ENABLE_LAYER1_READER", "true").lower() == "true",
        )


# Default list of SealedSecret files in docker-apps to blame for rotation
# age. Sourced from a 2026-06-09 inventory; refresh via SEALED_SECRET_PATHS
# env override if new SealedSecrets land.
_DEFAULT_SEALED_PATHS = [
    "monitoring/grafana/secrets.yaml",
    "monitoring/grafana/db-secret.yaml",
    "monitoring/postgres/secrets.yaml",
    "postgres/secrets.yaml",
    "apps/discord/secrets-conf.yaml",
    "apps/discord/secrets-vpn.yaml",
    "apps/eastbaymassage/secrets.yaml",
    "apps/mirror/concord/secrets.yaml",
    "apps/mirror/castro/secrets.yaml",
    "infrastructure/configs/cert-manager/cloudflare-api-key.yaml",
]
