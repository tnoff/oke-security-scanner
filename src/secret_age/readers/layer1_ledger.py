"""Layer-1 ledger reader: emits findings for admin tfvars that never reach
k8s. Source of truth is the terraform-managed `layer-1-rotation-ledger`
ConfigMap (in the security-scanner namespace).

The ConfigMap's `data` is a flat map of tfvar_name → YYYY-MM-DD,
populated from `var.layer1_rotation_dates` in terraform-admin and
plumbed through the apps/ stack. Operator updates the matching map
entry in the same commit that rotates the underlying secret.
"""

from datetime import date, datetime, timezone
from logging import getLogger

from kubernetes import client, config as k8s_config

from ..config import SecretAgeConfig
from ..finding import Finding, Layer, Severity

logger = getLogger(__name__)


def _grade(age_days: int, cfg: SecretAgeConfig) -> Severity:
    if age_days >= cfg.rotate_days:
        return Severity.ROTATE
    if age_days >= cfg.warn_days:
        return Severity.WARN
    return Severity.OK


def _parse_ledger_date(s: str) -> date | None:
    """Accept either bare YYYY-MM-DD or full RFC3339 (what terraform-admin
    auto-emits via time_static.<x>.rfc3339)."""
    if not s:
        return None
    if "T" in s:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        except ValueError:
            return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


def read_findings(cfg: SecretAgeConfig) -> list[Finding]:
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()

    v1 = client.CoreV1Api()
    try:
        cm = v1.read_namespaced_config_map(
            name=cfg.layer1_configmap_name,
            namespace=cfg.layer1_configmap_namespace,
        )
    except client.exceptions.ApiException as e:
        logger.warning(
            "layer-1 ledger ConfigMap %s/%s missing (%s) — skipping reader",
            cfg.layer1_configmap_namespace, cfg.layer1_configmap_name, e.status,
        )
        return []

    today = datetime.now(timezone.utc).date()
    findings: list[Finding] = []

    for tfvar, last_str in (cm.data or {}).items():
        last = _parse_ledger_date(last_str)
        if last is None:
            logger.warning(
                "layer1 ledger entry %s=%r is not YYYY-MM-DD or RFC3339 — skipping",
                tfvar, last_str,
            )
            continue
        age = (today - last).days
        findings.append(Finding(
            layer=Layer.LAYER1_LEDGER,
            identifier=f"tfvar {tfvar}",
            last_rotated=last,
            age_days=age,
            severity=_grade(age, cfg),
            rotation_command=(
                f"Rotate the underlying secret, then bump var.layer1_rotation_dates[\"{tfvar}\"] "
                f"to today in terraform-admin and re-apply"
            ),
            notes="Operator-maintained ledger — only as accurate as the last bump",
        ))

    logger.info("Layer-1 ledger reader: %d entries", len(findings))
    return findings
