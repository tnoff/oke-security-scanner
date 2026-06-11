"""Test the aggregator's bucketing + sorting."""

from datetime import date

from src.secret_age.aggregator import aggregate
from src.secret_age.finding import Finding, Layer, Severity


def _fix(identifier="x", layer=Layer.OCI_IAM, age=10, severity=Severity.OK):
    return Finding(
        layer=layer,
        identifier=identifier,
        last_rotated=date(2026, 1, 1),
        age_days=age,
        severity=severity,
        rotation_command="rotate",
    )


def test_aggregate_buckets_by_severity():
    findings = [
        _fix("a", age=300, severity=Severity.ROTATE),
        _fix("b", age=120, severity=Severity.WARN),
        _fix("c", age=10, severity=Severity.OK),
        Finding(
            layer=Layer.K8S_SECRET,
            identifier="d",
            last_rotated=None,
            age_days=None,
            severity=Severity.UNKNOWN,
            rotation_command="annotate",
        ),
    ]
    report = aggregate(findings)
    assert len(report.rotate_now) == 1
    assert len(report.warn) == 1
    assert len(report.unknown) == 1
    assert len(report.ok) == 1
    assert report.total == 4
    assert report.actionable == 3  # rotate + warn + unknown


def test_aggregate_sorts_rotate_oldest_first():
    findings = [
        _fix("newer", age=200, severity=Severity.ROTATE),
        _fix("older", age=400, severity=Severity.ROTATE),
        _fix("middle", age=300, severity=Severity.ROTATE),
    ]
    report = aggregate(findings)
    assert [f.identifier for f in report.rotate_now] == ["older", "middle", "newer"]


def test_aggregate_groups_by_layer():
    findings = [
        _fix("a", layer=Layer.OCI_IAM),
        _fix("b", layer=Layer.OCI_IAM),
        _fix("c", layer=Layer.K8S_SECRET),
    ]
    report = aggregate(findings)
    assert len(report.by_layer[Layer.OCI_IAM]) == 2
    assert len(report.by_layer[Layer.K8S_SECRET]) == 1
