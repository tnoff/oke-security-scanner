"""Discord webhook notification for scan results."""

import csv
from io import StringIO
from logging import getLogger
import time

from dappertable import DapperTable, DapperTableHeader, DapperTableHeaderOptions, PaginationLength
import requests

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

    def send_scan_report(
        self,
        scan_results: list[dict],
        total_critical: int,
        total_high: int,
        duration: float,
        total_images: int,
    ) -> bool:
        """Send formatted scan results to Discord.

        Args:
            scan_results: List of scan result dictionaries
            total_critical: Total count of critical vulnerabilities
            total_high: Total count of high vulnerabilities
            duration: Scan duration in seconds
            total_images: Total number of images scanned

        Returns:
            True if all messages sent successfully, False otherwise
        """
        try:
            # Build summary message
            summary = (
                f"Security Scan Complete\n"
                f"Scanned: {total_images} images in {duration:.1f}s\n"
                f"Critical: {total_critical} | High: {total_high}"
            )

            # Build table for Critical vulnerabilities WITH fixes only
            critical_with_fixes_table = self._build_vulnerability_table(
                scan_results, "CRITICAL", only_with_fixes=True
            )

            # Combine summary and critical-with-fixes table (may be paginated)
            messages = [summary]
            if critical_with_fixes_table:
                messages.extend(critical_with_fixes_table)

            # Generate CSV with all vulnerabilities
            csv_data = self._generate_csv(scan_results)

            # Send messages with CSV attached to first message only
            for idx, message in enumerate(messages):
                is_first = idx == 0
                csv_file = csv_data if is_first else None

                logger.debug(
                    f"Sending Discord message {idx + 1}/{len(messages)} "
                    f"({len(message)} chars{', with CSV' if is_first else ''})"
                )
                self._send_message(message, csv_file=csv_file)

                # Add delay between messages to avoid rate limiting (except after last message)
                if idx < len(messages) - 1:
                    time.sleep(1)

            logger.info(f"Successfully sent {len(messages)} Discord message(s) with CSV attachment")
            return True

        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False

    def _build_vulnerability_table(
        self, results: list[dict], severity: str, only_with_fixes: bool = False
    ) -> list[str]:
        """Build a table of vulnerabilities for a specific severity level.

        Args:
            results: List of scan result dictionaries
            severity: Severity level to filter (CRITICAL or HIGH)
            only_with_fixes: If True, only include vulnerabilities with available fixes

        Returns:
            List of message strings (paginated if needed)
        """
        # Define table headers with column widths
        headers = DapperTableHeaderOptions([
            DapperTableHeader("Image", 30),
            DapperTableHeader("CVE", 20),
            DapperTableHeader("Fixed", 15),
        ])

        # Create table with headers and pagination
        table = DapperTable(
            header_options=headers,
            pagination_options=PaginationLength(self.max_length),
            prefix=f"{severity} Vulnerabilities:\n",
            enclosure_start="```",
            enclosure_end="```",
        )

        # Collect all vulnerabilities for this severity
        rows = []
        for result in results:
            image = result.get("image", "unknown")
            cves = result.get("cves", {})

            # Extract short image name (remove registry prefix)
            short_name = image.split("/")[-1] if "/" in image else image

            for cve_id, details in cves.items():
                if details.get("severity") == severity:
                    fixed_version = details.get("fixed", "")

                    # Skip if filtering for fixes only and no fix available
                    if only_with_fixes and not fixed_version:
                        continue

                    fixed_status = fixed_version if fixed_version else "No fix"
                    rows.append([short_name, cve_id, fixed_status])

        # Sort rows by image name, then CVE ID
        rows.sort(key=lambda x: (x[0], x[1]))

        # Add rows to table
        for row in rows:
            table.add_row(row)

        # Return paginated messages
        messages = table.print()
        if isinstance(messages, str):
            return [messages]
        return messages

    def _generate_csv(self, results: list[dict]) -> str:
        """Generate CSV data for all vulnerabilities.

        Args:
            results: List of scan result dictionaries

        Returns:
            CSV data as a string
        """
        output = StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(["Image", "CVE", "Severity", "Fixed Version"])

        # Collect all vulnerabilities
        rows = []
        for result in results:
            image = result.get("image", "unknown")
            cves = result.get("cves", {})

            for cve_id, details in cves.items():
                severity = details.get("severity", "UNKNOWN")
                fixed_version = details.get("fixed", "")
                rows.append([image, cve_id, severity, fixed_version])

        # Sort by severity (CRITICAL first), then image, then CVE
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        rows.sort(key=lambda x: (severity_order.get(x[2], 99), x[0], x[1]))

        # Write rows
        for row in rows:
            writer.writerow(row)

        return output.getvalue()

    def _send_message(self, content: str, csv_file: str | None = None) -> None:
        """Send single message to Discord webhook.

        Args:
            content: Message content
            csv_file: Optional CSV file content to attach

        Raises:
            requests.HTTPError: If webhook request fails
        """
        if csv_file:
            # Send with file attachment using multipart/form-data
            files = {
                "file": ("vulnerabilities.csv", csv_file, "text/csv")
            }
            data = {"content": content}
            response = requests.post(
                self.webhook_url,
                data=data,
                files=files,
                timeout=10,
            )
        else:
            # Send as JSON payload (backward compatibility)
            payload = {"content": content}
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10,
            )
        response.raise_for_status()
