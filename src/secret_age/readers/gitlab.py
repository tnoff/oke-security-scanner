"""GitLab reader: blame each SealedSecret YAML in docker-apps for the last
commit that touched its `encryptedData` block, treat that as the
last-rotated date.

Also enumerates personal access tokens + group access tokens with their
expiry dates so the operator gets warned before something breaks.
"""

from datetime import date, datetime, timezone
from logging import getLogger
from typing import Iterable

import gitlab

from ..config import SecretAgeConfig
from ..finding import Finding, Layer, Severity

logger = getLogger(__name__)


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
    if not cfg.gitlab_token:
        logger.warning("GITLAB_TOKEN not set — skipping GitLab reader")
        return []

    gl = gitlab.Gitlab(cfg.gitlab_url, private_token=cfg.gitlab_token)
    findings: list[Finding] = []

    findings.extend(_blame_sealed_secrets(gl, cfg))
    findings.extend(_list_pat_expiries(gl, cfg))

    logger.info("GitLab reader: %d findings", len(findings))
    return findings


def _blame_sealed_secrets(gl: "gitlab.Gitlab", cfg: SecretAgeConfig) -> Iterable[Finding]:
    try:
        project = gl.projects.get(cfg.docker_apps_project)
    except gitlab.exceptions.GitlabGetError:
        logger.warning("docker-apps project %s not found via API — skipping blame", cfg.docker_apps_project)
        return []

    today = datetime.now(timezone.utc).date()
    out: list[Finding] = []

    for path in cfg.sealed_secret_paths:
        try:
            blame = project.files.blame(file_path=path, ref="main")
        except gitlab.exceptions.GitlabGetError:
            logger.warning("SealedSecret file %s missing in docker-apps — skipping", path)
            continue
        # blame is a list of {commit: {committed_date, ...}, lines: [...]}.
        # The newest commit across all ranges is the rotation date.
        committed_dates = [
            _to_date(b["commit"]["committed_date"])
            for b in blame if b.get("commit")
        ]
        if not committed_dates:
            continue
        last = max(committed_dates)
        age = (today - last).days
        out.append(Finding(
            layer=Layer.SEALED_SECRET,
            identifier=f"SealedSecret docker-apps/{path}",
            last_rotated=last,
            age_days=age,
            severity=_grade(age, cfg),
            rotation_command=(
                f"kubeseal --re-encrypt <(...new secret...) > {path}  # commit + push to docker-apps"
            ),
            notes=f"Last commit touched encryptedData on {last.isoformat()}",
        ))
    return out


def _list_pat_expiries(gl: "gitlab.Gitlab", cfg: SecretAgeConfig) -> Iterable[Finding]:
    """Report on PATs whose expiry is within the warn/rotate window.

    Uses the API's `expires_at` field directly — this is the *expiry*
    side of rotation, not the age side. age_days here is days_to_expiry
    (negative if already expired).
    """
    today = datetime.now(timezone.utc).date()
    out: list[Finding] = []

    try:
        pats = gl.personal_access_tokens.list(get_all=True)
    except gitlab.exceptions.GitlabListError as e:
        logger.warning("PAT list failed (token scope?): %s — skipping", e)
        return []

    for pat in pats:
        if not getattr(pat, "expires_at", None):
            continue
        expires = _to_date(pat.expires_at)
        days_to_expiry = (expires - today).days
        # Flag PATs expiring within the warn threshold; flip age sign so
        # the report reads "<n> days until expiry".
        if days_to_expiry > cfg.warn_days:
            continue
        severity = Severity.ROTATE if days_to_expiry <= 0 else Severity.WARN
        out.append(Finding(
            layer=Layer.SEALED_SECRET,  # surfaced under the GitLab group in the report
            identifier=f"GitLab PAT {pat.name} (id={pat.id})",
            last_rotated=expires,
            age_days=days_to_expiry,
            severity=severity,
            rotation_command=(
                "Rotate PAT in https://gitlab.com/-/user_settings/personal_access_tokens "
                "and update the matching tfvar in terraform-admin"
            ),
            notes=f"Expires {expires.isoformat()} ({days_to_expiry} days from now)",
        ))
    return out
