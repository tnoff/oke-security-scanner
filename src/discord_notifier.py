"""Discord webhook notification for scan results."""

import csv
from datetime import datetime
from io import StringIO
from logging import getLogger
import time
from typing import List

from dappertable import DapperTable, Column, Columns, PaginationLength
import requests

from .k8s_client import Image
from .scanner import CompleteScanResult
from .registry_client import CleanupRecommendation

logger = getLogger(__name__)

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

        full_report_table = DapperTable(columns=Columns([
            Column('Report Portion', 32),
            Column('Result', 8),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Scan Result Report\n')
        full_report_table.add_row(['Images Scanned', str(len(complete_scan_result.scan_results))])
        full_report_table.add_row(['Scans Failed', str(complete_scan_result.failed_scans)])
        full_report_table.add_row(['Critical (Fixed/Total)', f'{complete_scan_result.total_critical_fixed}/{complete_scan_result.total_critical}'])
        full_report_table.add_row(['High (Fixed/Total)', f'{complete_scan_result.total_high_fixed}/{complete_scan_result.total_high}'])


        critical_fixed_table = DapperTable(columns=Columns([
            Column('Image', 32),
            Column('CVE', 16),
            Column('Package', 16),
            Column('Fixed', 16)
            ]), pagination_options=PaginationLength(self.max_length), enclosure_end='```', enclosure_start='```',
                prefix='### Critical CVEs with Fixes\n')

        # Build csv
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(["Image", "CVE", "Severity", "Package", "Fixed Version"])
        for result in complete_scan_result.scan_results:
            for cve in result.cves:
                for detail in cve.details:
                    writer.writerow([f'{result.image.repo_name}:{result.image.tag}',
                                     cve.cve_id,
                                     detail.severity,
                                     detail.package,
                                     detail.fixed])
                    if detail.severity == 'CRITICAL' and detail.fixed:
                        critical_fixed_table.add_row([
                            f'{result.image.repo_name}:{result.image.tag}',
                            cve.cve_id,
                            detail.package,
                            detail.fixed,
                        ])
        failed_table = DapperTable(columns=Columns([
            Column('Image', 64),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='### Failed Scans\n')

        for image in complete_scan_result.failed_images:
            repo_name = f'{image.registry}/{image.repo_name}'
            if image.registry == 'docker.io':
                repo_name = image.repo_name
            failed_table.add_row([f'{repo_name}:{image.tag}'])

        message_content = []
        message_content += full_report_table.render()

        if len(failed_table):
            message_content += failed_table.render()
        if len(critical_fixed_table):
            message_content += critical_fixed_table.render()
        self._send_message(message_content)
        self._send_file('## Full Vulnerability CSV Report', output.getvalue(), f'{datetime.now().strftime("%Y-%m-%d")}.vulnerabilites.csv')

    def send_cleanup_recommendations(self, cleanup: list[CleanupRecommendation]):
        '''Send cleanup recommendation'''
        full_report_table = DapperTable(columns=Columns([
            Column('Image', 64),
            Column('Tag', 12),
            Column('Created At', 36),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix='## Images That Can Be Deleted\n')

        for report in cleanup:
            for tag in report.tags_to_delete:
                full_report_table.add_row([
                    f'{report.registry}/{report.repository}',
                    tag.tag,
                    tag.created_at.strftime('%Y-%m-%d %H-%M-%S')
                ])
        if len(full_report_table):
            content = full_report_table.render()
        else:
            content = ['## No Images That Require Deletion\n']
        self._send_message(content)

    def send_deletion_results(self, images: list[Image], is_orphaned: bool = False):
        '''Send deletion results'''
        prefix = '## Images Deleted\n'
        if is_orphaned:
            prefix = '## Orphan Intermediate Images Deleted\n'
        full_report_table = DapperTable(columns=Columns([
            Column('Image', 64),
            Column('Tag', 12),
        ]), pagination_options=PaginationLength(self.max_length), enclosure_start='```', enclosure_end='```',
        prefix=prefix)

        for image in images:
            output_tag = image.tag
            if image.tag == 'unknown':
                output_tag = image.digest
            full_report_table.add_row([
                f'{image.registry}/{image.repo_name}',
                output_tag,
            ])
        if len(full_report_table):
            content = full_report_table.render()
        else:
            content = ['## No images deleted\n']
        self._send_message(content)

    def _send_file(self, message_content: str, file_contents: str, file_name: str):
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
