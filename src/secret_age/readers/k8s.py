"""K8s Secret reader: list every Secret in the cluster, prefer the
`secret-age-tracker.tnoff/last-rotated` annotation over creationTimestamp.

Sentinel value `"unknown"` (set on every terraform-managed Secret as
the initial seed) means "no recorded rotation" — surfaced in the
report as a separate Severity.UNKNOWN bucket, never as age 0.

Requires `secrets [list]` cluster-wide; granted via a separate
ServiceAccount + ClusterRole in docker-apps so the existing scanner
SA doesn't inadvertently gain Secret read access.
"""

from datetime import date, datetime, timezone
from logging import getLogger

from kubernetes import client, config as k8s_config

from ..config import SecretAgeConfig
from ..finding import Finding, Layer, Severity

logger = getLogger(__name__)

ANNOTATION_KEY = "secret-age-tracker.tnoff/last-rotated"
SENTINEL = "unknown"

# K8s system Secrets — service-account tokens, helm releases, sealed-secrets
# encryption keys — don't represent operator-rotated credentials and just
# add noise. Filter by type.
_SKIP_SECRET_TYPES = {
    "kubernetes.io/service-account-token",
    "helm.sh/release.v1",
    "bootstrap.kubernetes.io/token",
}


def _grade(age_days: int, cfg: SecretAgeConfig) -> Severity:
    if age_days >= cfg.rotate_days:
        return Severity.ROTATE
    if age_days >= cfg.warn_days:
        return Severity.WARN
    return Severity.OK


def _to_date(ts) -> date:
    if isinstance(ts, datetime):
        return ts.date()
    if isinstance(ts, str):
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).date()
    return date.today()


def read_findings(cfg: SecretAgeConfig) -> list[Finding]:
    """Enumerate K8s Secrets and emit a Finding per non-system secret."""
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        # Local-dev fallback so the reader works outside the cluster too.
        k8s_config.load_kube_config()

    v1 = client.CoreV1Api()
    secrets = v1.list_secret_for_all_namespaces(watch=False).items
    logger.info("K8s reader: scanned %d secrets cluster-wide", len(secrets))

    today = datetime.now(timezone.utc).date()
    findings: list[Finding] = []

    for s in secrets:
        if s.type in _SKIP_SECRET_TYPES:
            continue

        annotations = s.metadata.annotations or {}
        annotated = annotations.get(ANNOTATION_KEY)

        if annotated == SENTINEL:
            # Initial-seed sentinel — surface for the operator to fill in.
            findings.append(Finding(
                layer=Layer.K8S_SECRET,
                identifier=f"{s.metadata.name} ({s.metadata.namespace}/)",
                last_rotated=None,
                age_days=None,
                severity=Severity.UNKNOWN,
                rotation_command=(
                    "After next rotation, set annotation "
                    f"{ANNOTATION_KEY}=YYYY-MM-DD in terraform/apps/main.tf "
                    "and re-apply"
                ),
                notes="Annotation = 'unknown' (initial seed). Track rotation history forward from next rotation.",
            ))
            continue

        if annotated:
            try:
                last = _to_date(annotated)
            except ValueError:
                logger.warning(
                    "K8s Secret %s/%s has malformed annotation %r — skipping",
                    s.metadata.namespace, s.metadata.name, annotated,
                )
                continue
        else:
            # No annotation at all — fall back to creationTimestamp.
            # Note: this lies for terraform-managed Secrets where data
            # was updated in place without -replace. Annotated Secrets
            # are the trustworthy path.
            last = _to_date(s.metadata.creation_timestamp)

        age = (today - last).days
        findings.append(Finding(
            layer=Layer.K8S_SECRET,
            identifier=f"{s.metadata.name} ({s.metadata.namespace}/)",
            last_rotated=last,
            age_days=age,
            severity=_grade(age, cfg),
            rotation_command=(
                "terraform apply -replace=kubernetes_secret_v1.<resource>  # in terraform/apps/"
                if annotated else
                f"kubectl -n {s.metadata.namespace} annotate secret "
                f"{s.metadata.name} {ANNOTATION_KEY}=<YYYY-MM-DD>  # at least record next rotation"
            ),
            notes=f"Source: {'annotation' if annotated else 'creationTimestamp (unreliable)'}",
        ))

    return findings
