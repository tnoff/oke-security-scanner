"""Format the Report as a Discord webhook payload and send it.

Modeled on src/discord_notifier.py — same 2000-char limit, same
DapperTable styling for monospace tables.
"""

from logging import getLogger

from dappertable import DapperTable, Column, Columns, PaginationLength
import requests

from .aggregator import Report
from .finding import Finding, Layer

logger = getLogger(__name__)

MAX_LEN = 2000
LAYER_TITLES = {
    Layer.OCI_IAM: "OCI IAM credentials",
    Layer.K8S_SECRET: "Kubernetes Secrets",
    Layer.SEALED_SECRET: "SealedSecrets + GitLab PATs",
    Layer.LAYER1_LEDGER: "Layer-1 admin tfvars (operator-tracked)",
}


def send_report(webhook_url: str, report: Report) -> None:
    if not webhook_url:
        logger.warning("DISCORD_WEBHOOK_URL not set — skipping report send")
        return

    chunks = list(_format_chunks(report))
    for chunk in chunks:
        resp = requests.post(webhook_url, json={"content": chunk}, timeout=15)
        resp.raise_for_status()
    logger.info("Sent %d Discord chunks", len(chunks))


def _format_chunks(report: Report):
    summary = (
        f"## Secret-age tracker report\n"
        f"- **Rotate now (≥180d)**: {len(report.rotate_now)}\n"
        f"- **Warn (≥90d)**: {len(report.warn)}\n"
        f"- **Unknown (annotation = 'unknown')**: {len(report.unknown)}\n"
        f"- **OK**: {len(report.ok)}\n"
        f"- **Total tracked**: {report.total}\n"
    )
    yield summary

    if report.rotate_now:
        yield from _table("🔴 Rotate now (≥180d)", report.rotate_now)
    if report.warn:
        yield from _table("🟡 Warn (≥90d)", report.warn)
    if report.unknown:
        yield from _table("⚪ Unknown — set on next rotation", report.unknown, show_age=False)


def _table(title: str, findings: list[Finding], show_age: bool = True):
    columns = [
        Column("Identifier", 40),
        Column("Layer", 14),
    ]
    if show_age:
        columns.append(Column("Age (d)", 8))
    table = DapperTable(
        columns=Columns(columns),
        pagination_options=PaginationLength(MAX_LEN),
        enclosure_start="```",
        enclosure_end="```",
        prefix=f"### {title}\n",
    )
    for f in findings:
        row = [f.identifier[:40], f.layer.value]
        if show_age:
            row.append(str(f.age_days) if f.age_days is not None else "—")
        table.add_row(row)
    # `.render()` returns a list of paginated string chunks already wrapped
    # in the enclosure marks. `.get_pages()` returns DapperRow objects which
    # aren't JSON-serializable.
    yield from table.render()
