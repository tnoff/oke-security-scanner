"""Finding dataclass: one row in the rotation report."""

from dataclasses import dataclass
from datetime import date
from enum import Enum


class Layer(str, Enum):
    """Which storage layer the secret lives in."""
    OCI_IAM = "oci-iam"
    K8S_SECRET = "k8s-secret"  # nosec B105 — enum label, not a credential
    SEALED_SECRET = "sealed-secret"  # nosec B105 — enum label, not a credential
    LAYER1_LEDGER = "layer1-ledger"


class Severity(str, Enum):
    """How urgent rotation is for a given finding."""
    OK = "ok"          # under WARN_DAYS
    WARN = "warn"      # WARN_DAYS ≤ age < ROTATE_DAYS
    ROTATE = "rotate"  # age ≥ ROTATE_DAYS
    UNKNOWN = "unknown"  # sentinel — annotation set to "unknown", no real date


@dataclass(frozen=True)
class Finding:
    """One identified secret with a known (or sentinel) last-rotated date.

    age_days is None when last_rotated is None (sentinel "unknown"
    annotation or missing ledger entry); the aggregator surfaces those
    as "set this on next rotation" rather than computing a fake age.
    """
    layer: Layer
    identifier: str          # human-readable: "discord-os-credentials (discord/)" etc.
    last_rotated: date | None
    age_days: int | None
    severity: Severity
    rotation_command: str    # e.g. "terraform apply -replace=grafana_service_account_token.mcp_grafana"
    notes: str = ""          # free-form: which OCI user, which file, etc.
