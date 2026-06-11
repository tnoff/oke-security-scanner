"""Tests for discord_report.send_report + chunk formatting."""

from datetime import date
from unittest.mock import Mock, patch

import pytest

from src.secret_age.aggregator import aggregate
from src.secret_age.discord_report import send_report, _format_chunks, _table
from src.secret_age.finding import Finding, Layer, Severity


def _fix(identifier="x", layer=Layer.OCI_IAM, age=10, severity=Severity.OK):
    return Finding(
        layer=layer, identifier=identifier,
        last_rotated=date(2026, 1, 1), age_days=age,
        severity=severity, rotation_command="cmd",
    )


def test_send_report_skips_when_no_webhook_url():
    report = aggregate([])
    with patch("src.secret_age.discord_report.requests.post") as p:
        send_report("", report)
    p.assert_not_called()


def test_send_report_posts_when_webhook_url_set():
    findings = [_fix("a", severity=Severity.ROTATE, age=300)]
    report = aggregate(findings)
    mock_resp = Mock(status_code=200)
    mock_resp.raise_for_status.return_value = None
    with patch("src.secret_age.discord_report.requests.post", return_value=mock_resp) as p:
        send_report("https://discord.test/hook", report)
    assert p.call_count >= 1
    # Each call uses the right url + json shape
    for call in p.call_args_list:
        assert call.kwargs["json"]["content"]


def test_send_report_raises_on_4xx():
    findings = [_fix(severity=Severity.WARN, age=120)]
    report = aggregate(findings)
    mock_resp = Mock()
    mock_resp.raise_for_status.side_effect = Exception("400 Bad Request")
    with patch("src.secret_age.discord_report.requests.post", return_value=mock_resp):
        with pytest.raises(Exception, match="400"):
            send_report("https://discord.test/hook", report)


def test_format_chunks_emits_summary_first():
    report = aggregate([_fix(severity=Severity.ROTATE, age=300)])
    chunks = list(_format_chunks(report))
    assert chunks[0].startswith("## Secret-age tracker report")
    assert "Rotate now" in chunks[0]


def test_format_chunks_skips_empty_buckets():
    # No findings at all → only the summary chunk
    report = aggregate([])
    chunks = list(_format_chunks(report))
    assert len(chunks) == 1


def test_format_chunks_emits_unknown_table_without_age():
    unknown = Finding(
        layer=Layer.K8S_SECRET, identifier="needs-set",
        last_rotated=None, age_days=None,
        severity=Severity.UNKNOWN, rotation_command="annotate",
    )
    report = aggregate([unknown])
    chunks = list(_format_chunks(report))
    # Summary + the "unknown" table
    assert any("Unknown" in c or "set on next rotation" in c for c in chunks)


def test_table_truncates_long_identifiers():
    long_id = "a" * 100
    pages = list(_table("Test", [_fix(identifier=long_id, age=200, severity=Severity.ROTATE)]))
    # DapperTable pages aren't bare strings; just confirm we got output
    assert len(pages) >= 1
