"""Tests for discord_report.send_report + chunk formatting."""

from datetime import date
from unittest.mock import Mock, patch

import pytest

from src.secret_age.aggregator import aggregate
from src.secret_age.discord_report import send_report, _build_csv, _format_chunks, _table
from src.secret_age.finding import Finding, Layer, Severity


def _fix(identifier="x", layer=Layer.OCI_IAM, age=10, severity=Severity.OK,
         rotation_command="cmd", notes=""):
    return Finding(
        layer=layer, identifier=identifier,
        last_rotated=date(2026, 1, 1), age_days=age,
        severity=severity, rotation_command=rotation_command, notes=notes,
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
    # Message chunks post JSON; the trailing CSV attachment posts multipart
    # (data + files) instead. Every call must be one or the other.
    for call in p.call_args_list:
        if "json" in call.kwargs:
            assert call.kwargs["json"]["content"]
        else:
            assert call.kwargs["files"]["file"]
            assert call.kwargs["data"]["content"]


def test_send_report_attaches_full_detail_csv():
    findings = [_fix("a", severity=Severity.ROTATE, age=300)]
    report = aggregate(findings)
    mock_resp = Mock(status_code=200)
    mock_resp.raise_for_status.return_value = None
    with patch("src.secret_age.discord_report.requests.post", return_value=mock_resp) as p:
        send_report("https://discord.test/hook", report)
    file_calls = [c for c in p.call_args_list if "files" in c.kwargs]
    assert len(file_calls) == 1
    name, contents, mime = file_calls[0].kwargs["files"]["file"]
    assert name.endswith(".secret-ages.csv")
    assert mime == "text/csv"
    assert "Rotation Command" in contents


def test_build_csv_includes_all_severities_and_full_detail():
    findings = [
        _fix("rotate-me", severity=Severity.ROTATE, age=300,
             rotation_command="terraform apply -replace=foo", notes="oci user bar"),
        _fix("ok-secret", severity=Severity.OK, age=5),
        Finding(layer=Layer.K8S_SECRET, identifier="needs-set",
                last_rotated=None, age_days=None, severity=Severity.UNKNOWN,
                rotation_command="annotate", notes="set on next rotation"),
    ]
    csv_text = _build_csv(aggregate(findings))
    # OK rows are dropped from the Discord tables but must appear in the CSV.
    assert "ok-secret" in csv_text
    # Full detail the tables truncate/omit is present.
    assert "terraform apply -replace=foo" in csv_text
    assert "oci user bar" in csv_text
    # Sentinel "unknown" rows render with empty date/age, not a fabricated value.
    assert "needs-set,,," in csv_text or ",needs-set,," in csv_text


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


def test_table_yields_string_chunks():
    # render() returns strings, not DapperRow objects; chunks JSON-serialize.
    pages = list(_table("Test", [_fix(identifier="x", age=200, severity=Severity.ROTATE)]))
    assert len(pages) >= 1
    assert all(isinstance(p, str) for p in pages)
