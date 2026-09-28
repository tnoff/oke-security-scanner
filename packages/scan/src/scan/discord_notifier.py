"""Discord webhook notification for scan results."""

import csv
from datetime import datetime
from io import StringIO
from logging import getLogger

from dappertable import DapperTable, Column, Columns, PaginationLength
from oke_scanner_core.discord_webhook import DiscordWebhookClient

from .scanner import CompleteScanResult

logger = getLogger(__name__)

class DiscordNotifier:
    """Send scan results to Discord via webhook."""

    def __init__(self, webhook_url: str):
        """Initialize Discord notifier.

        Args:
            webhook_url: Discord webhook URL
        """
        self._client = DiscordWebhookClient(webhook_url)

    def send_image_scan_report(self, complete_scan_result: CompleteScanResult):
        '''Send complete scan report to discord'''
        max_length = self._client.max_length

        full_report_table = DapperTable(columns=Columns([
            Column('Report Portion', 32),
            Column('Result', 8),
        ]), pagination_options=PaginationLength(max_length), enclosure_start='```', enclosure_end='```',
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
            ]), pagination_options=PaginationLength(max_length), enclosure_end='```', enclosure_start='```',
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
        ]), pagination_options=PaginationLength(max_length), enclosure_start='```', enclosure_end='```',
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
        self._client.send_message(message_content)
        self._client.send_file('## Full Vulnerability CSV Report', output.getvalue(), f'{datetime.now().strftime("%Y-%m-%d")}.vulnerabilites.csv')
