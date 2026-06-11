"""Tests for readers.k8s — enumerates k8s Secrets, prefers annotation."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.secret_age.finding import Severity
from src.secret_age.readers.k8s import (
    read_findings, _grade, _to_date, ANNOTATION_KEY, SENTINEL, _SKIP_SECRET_TYPES,
)


def _secret(name, namespace, type_="Opaque", annotations=None, created=None):
    meta = Mock()
    meta.name = name
    meta.namespace = namespace
    meta.annotations = annotations or {}
    meta.creation_timestamp = created or datetime(2026, 1, 1, tzinfo=timezone.utc)
    s = Mock()
    s.metadata = meta
    s.type = type_
    return s


def _api_with(secrets):
    api = Mock()
    api.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=secrets)
    return api


def test_grade_thresholds(cfg):
    assert _grade(89, cfg) == Severity.OK
    assert _grade(90, cfg) == Severity.WARN
    assert _grade(181, cfg) == Severity.ROTATE


def test_to_date_handles_str_iso():
    assert _to_date("2026-04-12T00:00:00Z").year == 2026
    assert _to_date(datetime(2026, 1, 1)).year == 2026


def test_read_findings_skips_system_secret_types(cfg):
    secrets = [
        _secret("sa-token", "default", type_="kubernetes.io/service-account-token"),
        _secret("helm-rel", "default", type_="helm.sh/release.v1"),
        _secret("bootstrap", "kube-system", type_="bootstrap.kubernetes.io/token"),
    ]
    with patch("src.secret_age.readers.k8s.k8s_config") as kc, \
         patch("src.secret_age.readers.k8s.client.CoreV1Api", return_value=_api_with(secrets)):
        kc.load_incluster_config.return_value = None
        kc.ConfigException = Exception
        findings = read_findings(cfg)
    assert findings == []


def test_read_findings_unknown_sentinel_surfaces(cfg):
    secrets = [_secret("flux-system-https", "flux-system", annotations={ANNOTATION_KEY: SENTINEL})]
    with patch("src.secret_age.readers.k8s.k8s_config") as kc, \
         patch("src.secret_age.readers.k8s.client.CoreV1Api", return_value=_api_with(secrets)):
        kc.load_incluster_config.return_value = None
        kc.ConfigException = Exception
        findings = read_findings(cfg)
    assert len(findings) == 1
    assert findings[0].severity == Severity.UNKNOWN
    assert findings[0].age_days is None


def test_read_findings_annotation_overrides_creation_timestamp(cfg):
    # creation_timestamp is "young" but annotation says "old"
    secrets = [_secret(
        "discord-os-credentials", "discord",
        annotations={ANNOTATION_KEY: "2025-01-01"},
        created=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )]
    with patch("src.secret_age.readers.k8s.k8s_config") as kc, \
         patch("src.secret_age.readers.k8s.client.CoreV1Api", return_value=_api_with(secrets)):
        kc.load_incluster_config.return_value = None
        kc.ConfigException = Exception
        findings = read_findings(cfg)
    assert len(findings) == 1
    assert findings[0].age_days > 180  # old per annotation
    assert findings[0].severity == Severity.ROTATE


def test_read_findings_falls_back_to_creation_when_no_annotation(cfg):
    secrets = [_secret(
        "discord-metadata", "discord",
        annotations=None,
        created=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )]
    with patch("src.secret_age.readers.k8s.k8s_config") as kc, \
         patch("src.secret_age.readers.k8s.client.CoreV1Api", return_value=_api_with(secrets)):
        kc.load_incluster_config.return_value = None
        kc.ConfigException = Exception
        findings = read_findings(cfg)
    assert len(findings) == 1
    assert "creationTimestamp" in findings[0].notes


def test_read_findings_malformed_annotation_skipped(cfg):
    secrets = [_secret(
        "bad-anno", "default",
        annotations={ANNOTATION_KEY: "not-a-date"},
    )]
    with patch("src.secret_age.readers.k8s.k8s_config") as kc, \
         patch("src.secret_age.readers.k8s.client.CoreV1Api", return_value=_api_with(secrets)):
        kc.load_incluster_config.return_value = None
        kc.ConfigException = Exception
        findings = read_findings(cfg)
    assert findings == []


def test_to_date_fallback_on_unknown_type():
    # Intentionally pass something neither datetime nor str → today
    assert _to_date(12345) is not None


def test_read_findings_kubeconfig_fallback(cfg):
    secrets = []
    api = _api_with(secrets)
    with patch("src.secret_age.readers.k8s.k8s_config") as kc, \
         patch("src.secret_age.readers.k8s.client.CoreV1Api", return_value=api):
        kc.ConfigException = Exception
        kc.load_incluster_config.side_effect = kc.ConfigException("not in cluster")
        kc.load_kube_config.return_value = None
        findings = read_findings(cfg)
    kc.load_kube_config.assert_called_once()
    assert findings == []
