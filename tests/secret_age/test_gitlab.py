"""Tests for readers.gitlab — blames SealedSecret files + lists PAT expiries."""

from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

import gitlab as gitlab_lib

from src.secret_age.finding import Layer, Severity
from src.secret_age.readers.gitlab import (
    read_findings, _blame_sealed_secrets, _list_pat_expiries, _to_date, _grade,
)


def test_to_date_variants():
    assert _to_date(datetime(2026, 4, 1, tzinfo=timezone.utc)).year == 2026
    assert _to_date("2026-04-01T12:00:00Z").year == 2026
    # Fallback path for non-datetime/non-str input
    assert _to_date(12345) is not None


def test_grade_buckets(cfg):
    assert _grade(50, cfg) == Severity.OK
    assert _grade(100, cfg) == Severity.WARN
    assert _grade(200, cfg) == Severity.ROTATE


def test_read_findings_skips_when_no_token(cfg):
    cfg.gitlab_token = ""
    assert read_findings(cfg) == []


def test_read_findings_calls_both_readers(cfg):
    with patch("src.secret_age.readers.gitlab.gitlab.Gitlab") as gl_class, \
         patch("src.secret_age.readers.gitlab._blame_sealed_secrets", return_value=[]) as blame, \
         patch("src.secret_age.readers.gitlab._list_pat_expiries", return_value=[]) as pats:
        gl_class.return_value = Mock()
        read_findings(cfg)
    blame.assert_called_once()
    pats.assert_called_once()


def test_blame_emits_finding_per_file(cfg):
    project = Mock()
    project.files.blame.return_value = [
        {"commit": {"committed_date": "2025-01-01T00:00:00Z"}},
        {"commit": {"committed_date": "2025-08-01T00:00:00Z"}},  # newest
    ]
    gl = Mock()
    gl.projects.get.return_value = project
    findings = list(_blame_sealed_secrets(gl, cfg))
    assert len(findings) == 1
    assert findings[0].layer == Layer.SEALED_SECRET
    assert "2025-08-01" in findings[0].notes


def test_blame_handles_missing_project(cfg):
    gl = Mock()
    gl.projects.get.side_effect = gitlab_lib.exceptions.GitlabGetError("404")
    assert list(_blame_sealed_secrets(gl, cfg)) == []


def test_blame_handles_missing_file(cfg):
    project = Mock()
    project.files.blame.side_effect = gitlab_lib.exceptions.GitlabGetError("404")
    gl = Mock()
    gl.projects.get.return_value = project
    assert list(_blame_sealed_secrets(gl, cfg)) == []


def test_blame_skips_files_with_no_commit_data(cfg):
    project = Mock()
    project.files.blame.return_value = [{"lines": ["..."]}]  # no commit key
    gl = Mock()
    gl.projects.get.return_value = project
    assert list(_blame_sealed_secrets(gl, cfg)) == []


def test_pat_expiries_within_warn_surface_warn(cfg):
    pat = SimpleNamespace(
        id=42, name="mcp-gitlab",
        expires_at=(date.today().replace(year=date.today().year + 0)).isoformat(),
    )
    # Force expires_at to ~30 days out
    today = datetime.now(timezone.utc).date()
    from datetime import timedelta
    pat.expires_at = (today + timedelta(days=30)).isoformat()

    gl = Mock()
    gl.personal_access_tokens.list.return_value = [pat]
    out = list(_list_pat_expiries(gl, cfg))
    assert len(out) == 1
    assert out[0].severity == Severity.WARN


def test_pat_expiries_already_expired_surface_rotate(cfg):
    from datetime import timedelta
    today = datetime.now(timezone.utc).date()
    pat = SimpleNamespace(id=1, name="old", expires_at=(today - timedelta(days=5)).isoformat())
    gl = Mock()
    gl.personal_access_tokens.list.return_value = [pat]
    out = list(_list_pat_expiries(gl, cfg))
    assert len(out) == 1
    assert out[0].severity == Severity.ROTATE


def test_pat_expiries_far_future_skipped(cfg):
    from datetime import timedelta
    today = datetime.now(timezone.utc).date()
    pat = SimpleNamespace(id=2, name="fresh", expires_at=(today + timedelta(days=300)).isoformat())
    gl = Mock()
    gl.personal_access_tokens.list.return_value = [pat]
    out = list(_list_pat_expiries(gl, cfg))
    assert out == []


def test_pat_expiries_no_expiry_skipped(cfg):
    pat = SimpleNamespace(id=3, name="forever", expires_at=None)
    gl = Mock()
    gl.personal_access_tokens.list.return_value = [pat]
    out = list(_list_pat_expiries(gl, cfg))
    assert out == []


def test_pat_expiries_handles_list_error(cfg):
    gl = Mock()
    gl.personal_access_tokens.list.side_effect = gitlab_lib.exceptions.GitlabListError("no perm")
    out = list(_list_pat_expiries(gl, cfg))
    assert out == []
