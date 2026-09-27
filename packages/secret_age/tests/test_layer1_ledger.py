"""Tests for layer-1 ledger reader (ConfigMap-backed)."""

from datetime import date, datetime, timezone
from unittest.mock import Mock, patch

from kubernetes import client as k8s_client

from secret_age.finding import Layer, Severity
from secret_age.readers.layer1_ledger import _parse_ledger_date, read_findings


def test_parse_bare_date():
    assert _parse_ledger_date("2026-06-10") == date(2026, 6, 10)


def test_parse_rfc3339_utc_z():
    assert _parse_ledger_date("2026-06-10T15:30:45Z") == date(2026, 6, 10)


def test_parse_rfc3339_with_offset():
    assert _parse_ledger_date("2026-06-10T15:30:45+00:00") == date(2026, 6, 10)


def test_parse_invalid_returns_none():
    assert _parse_ledger_date("not-a-date") is None
    assert _parse_ledger_date("") is None
    assert _parse_ledger_date("2026-13-99") is None
    # RFC3339-shaped but invalid date components hit the ValueError branch
    assert _parse_ledger_date("2026-13-99T00:00:00Z") is None


def _api_with(data):
    cm = Mock()
    cm.data = data
    api = Mock()
    api.read_namespaced_config_map.return_value = cm
    return api


def test_read_findings_no_configmap(cfg):
    api = Mock()
    err = k8s_client.exceptions.ApiException(status=404, reason="Not Found")
    api.read_namespaced_config_map.side_effect = err
    with patch("secret_age.readers.layer1_ledger.load_k8s_config"), \
         patch("secret_age.readers.layer1_ledger.client.CoreV1Api", return_value=api):
        findings = read_findings(cfg)
    assert findings == []


def test_read_findings_emits_per_ledger_entry(cfg):
    data = {
        "discord_token": "2025-01-01T00:00:00Z",  # very old → ROTATE
        "ssh_public_key": "2026-06-01",  # recent
    }
    with patch("secret_age.readers.layer1_ledger.load_k8s_config"), \
         patch("secret_age.readers.layer1_ledger.client.CoreV1Api", return_value=_api_with(data)):
        findings = read_findings(cfg)
    assert len(findings) == 2
    assert all(f.layer == Layer.LAYER1_LEDGER for f in findings)
    rotate = next(f for f in findings if f.identifier == "tfvar discord_token")
    assert rotate.severity == Severity.ROTATE


def test_read_findings_skips_malformed_dates(cfg):
    data = {"good_var": "2026-06-01", "bad_var": "tomorrow"}
    with patch("secret_age.readers.layer1_ledger.load_k8s_config"), \
         patch("secret_age.readers.layer1_ledger.client.CoreV1Api", return_value=_api_with(data)):
        findings = read_findings(cfg)
    assert len(findings) == 1
    assert findings[0].identifier == "tfvar good_var"


def test_read_findings_handles_empty_configmap(cfg):
    with patch("secret_age.readers.layer1_ledger.load_k8s_config"), \
         patch("secret_age.readers.layer1_ledger.client.CoreV1Api", return_value=_api_with(None)):
        findings = read_findings(cfg)
    assert findings == []


def test_read_findings_loads_k8s_config(cfg):
    # The incluster/kubeconfig-fallback behavior itself is oke_scanner_core's
    # own responsibility and coverage; this only checks read_findings wires it in.
    api = _api_with({"x": "2026-01-01"})
    with patch("secret_age.readers.layer1_ledger.load_k8s_config") as load_config, \
         patch("secret_age.readers.layer1_ledger.client.CoreV1Api", return_value=api):
        read_findings(cfg)
    load_config.assert_called_once()
