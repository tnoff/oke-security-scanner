"""Combine reader outputs into a single report dataclass."""

from dataclasses import dataclass, field
from logging import getLogger

from .finding import Finding, Layer, Severity

logger = getLogger(__name__)


@dataclass
class Report:
    """Aggregated tracker output, grouped for display."""
    by_layer: dict[Layer, list[Finding]] = field(default_factory=dict)
    rotate_now: list[Finding] = field(default_factory=list)
    warn: list[Finding] = field(default_factory=list)
    unknown: list[Finding] = field(default_factory=list)
    ok: list[Finding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.by_layer.values())

    @property
    def actionable(self) -> int:
        return len(self.rotate_now) + len(self.warn) + len(self.unknown)


def aggregate(findings: list[Finding]) -> Report:
    """Bucket findings by layer + severity for the report."""
    r = Report()
    for f in findings:
        r.by_layer.setdefault(f.layer, []).append(f)
        if f.severity == Severity.ROTATE:
            r.rotate_now.append(f)
        elif f.severity == Severity.WARN:
            r.warn.append(f)
        elif f.severity == Severity.UNKNOWN:
            r.unknown.append(f)
        else:
            r.ok.append(f)

    # Within each bucket, sort oldest-first so the most urgent rows
    # show at the top of the Discord embed.
    def _sort_key(f: Finding):
        return -(f.age_days or 0)

    r.rotate_now.sort(key=_sort_key)
    r.warn.sort(key=_sort_key)
    r.unknown.sort(key=lambda f: f.identifier)

    logger.info(
        "Aggregate: total=%d rotate=%d warn=%d unknown=%d ok=%d",
        r.total, len(r.rotate_now), len(r.warn), len(r.unknown), len(r.ok),
    )
    return r
