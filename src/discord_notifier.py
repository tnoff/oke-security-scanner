"""Discord webhook notification for scan results."""

import csv
from datetime import datetime
from io import StringIO
from logging import getLogger
import time
from typing import List

from dappertable import DapperTable, DapperTableHeader, DapperTableHeaderOptions, PaginationLength
from opentelemetry import trace
import requests

from .k8s_client import Image
from .scanner import CompleteScanResult
from .registry_client import UpdateInfo, CleanupRecommendation

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)

OTEL_PREFIX = 'discord'

class DiscordNotifier:
    """Send scan results to Discord via webhook."""

    def __init__(self, webhook_url: str):
        """Initialize Discord notifier.

        Args:
            webhook_url: Discord webhook URL
        """
        self.webhook_url = webhook_url
        self.max_length = 2000  # Discord message character limit

    def send_image_scan_report(self, complete_scan_result: CompleteScanResult):
        '''Send complete scan report to discord'''

        full_report_table = DapperTable(header_options=DapperTableHeaderOptions([
            DapperTableHeader('Report Portion', 32),
            DapperTableHeader('Result', 8),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Scan Result Report\n')
        full_report_table.add_row(['Images Scanned', len(complete_scan_result.scan_results)])
        full_report_table.add_row(['Scans Failed', complete_scan_result.failed_scans])
        full_report_table.add_row(['Critical (Fixed/Total)', f'{complete_scan_result.total_critical_fixed}/{complete_scan_result.total_critical}'])
        full_report_table.add_row(['High (Fixed/Total)', f'{complete_scan_result.total_high_fixed}/{complete_scan_result.total_high}'])


        critical_fixed_table = DapperTable(header_options=DapperTableHeaderOptions([
            DapperTableHeader('Image', 64),
            DapperTableHeader('CVE', 16),
            DapperTableHeader('Fixed', 32)
            ]), pagination_options=PaginationLength(self.max_length), enclosure_end='```', enclosure_start='```',
                prefix='### Critical CVEs with Fixes\n')

        # Build csv
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(["Image", "CVE", "Severity", "Fixed Version"])
        for result in complete_scan_result.scan_results:
            for cve in result.cves:
                for detail in cve.details:
                    writer.writerow([result.image.full_name,
                                     cve.cve_id,
                                     detail.severity,
                                     detail.fixed])
                    if detail.severity == 'CRITICAL' and detail.fixed:
                        critical_fixed_table.add_row([
                            result.image.full_name,
                            cve.cve_id,
                            detail.fixed,
                        ])
        message_content = []
        message_content += full_report_table.print()

        if critical_fixed_table.size:
            message_content += critical_fixed_table.print()
        self._send_message(message_content)
        self._send_file('## Full Vulnerability CSV Report', output.getvalue(), f'{datetime.now().strftime("%Y-%m-%d")}.vulnerabilites.csv')

    def send_version_update_info(self, update_info: list[UpdateInfo]):
        '''Send update info to discord'''

        full_report_table = DapperTable(header_options=DapperTableHeaderOptions([
            DapperTableHeader('Image', 64),
            DapperTableHeader('Current', 12),
            DapperTableHeader('Available', 12),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Image Updates Available\n')

        for info in update_info:
            repo_name = f'{info.registry}/{info.repo_name}'
            if info.registry == 'docker.io':
                repo_name = info.repo_name
            full_report_table.add_row([
                repo_name,
                info.current,
                info.latest,
            ])
        content = []
        if not full_report_table.size:
            content = ['## No Image Updates Found\n']
        else:
            content = full_report_table.print()
        self._send_message(content)

    def send_cleanup_recommendations(self, cleanup: list[CleanupRecommendation]):
        '''Send cleanup recommendation'''
        full_report_table = DapperTable(header_options=DapperTableHeaderOptions([
            DapperTableHeader('Image', 64),
            DapperTableHeader('Tag', 12),
            DapperTableHeader('Created At', 36),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Images That Can Be Deleted\n')

        for report in cleanup:
            for tag in report.tags_to_delete:
                full_report_table.add_row([
                    f'{report.registry}/{report.repository}',
                    tag.tag,
                    tag.created_at.strftime('%Y-%m-%d %H-%M-%S')
                ])
        content = []
        if full_report_table.size < 1:
            content = ['## No Images That Require Deletion\n']
        else:
            content = full_report_table.print()
        self._send_message(content)

    def send_deletion_results(self, images: list[Image]):
        '''Send deletion results'''
        full_report_table = DapperTable(header_options=DapperTableHeaderOptions([
            DapperTableHeader('Image', 64),
            DapperTableHeader('Tag', 12),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Images Deleted\n')

        for image in images:
            full_report_table.add_row([
                f'{image.registry}/{image.repo_name}',
                image.tag,
            ])
        content = []
        if full_report_table.size < 1:
            content = ['## No images deleted\n']
        else:
            content = full_report_table.print()
        self._send_message(content)

    def _send_file(self, message_content: str, file_contents: str, file_name: str):
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.send_file'):
            # Send with file attachment using multipart/form-data
            files = {
                "file": (file_name, file_contents, "text/csv")
            }
            data = {"content": message_content}
            response = requests.post(
                self.webhook_url,
                data=data,
                files=files,
                timeout=10,
            )
            response.raise_for_status()

    def _send_message(self, content_list: List[str]) -> None:
        """Send single message to Discord webhook.

        Args:
            content: Message content
            csv_file: Optional CSV file content to attach

        Raises:
            requests.HTTPError: If webhook request fails
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.send_message'):
            for content in content_list:
                # Send as JSON payload (backward compatibility)
                payload = {"content": content}
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10,
                )
                response.raise_for_status()
                # Sleep one second to avoid rate limiting
                time.sleep(1)
