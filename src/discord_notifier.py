"""Discord webhook notification for scan results."""

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
            messages = []

            # Build summary message
            summary = (
                f"Security Scan Complete\n"
                f"Scanned: {total_images} images in {duration:.1f}s\n"
                f"Critical: {total_critical} | High: {total_high}"
            )
            messages.append(summary)

            # Build Critical vulnerabilities table
            if total_critical > 0:
                critical_table = self._build_vulnerability_table(scan_results, "CRITICAL")
                if critical_table:
                    messages.extend(critical_table)

            # Build High vulnerabilities table
            if total_high > 0:
                high_table = self._build_vulnerability_table(scan_results, "HIGH")
                if high_table:
                    messages.extend(high_table)

            # Send each message with rate limiting delay
            for idx, msg in enumerate(messages, 1):
                logger.debug(f"Sending Discord message {idx}/{len(messages)} ({len(msg)} chars)")
                self._send_message(msg)
                # Add delay between messages to avoid rate limiting (except after last message)
                if idx < len(messages):
                    time.sleep(1)

            logger.info(f"Successfully sent {len(messages)} Discord message(s)")
            return True

        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False

    def _build_vulnerability_table(self, results: list[dict], severity: str) -> list[str]:
        """Build a table of vulnerabilities for a specific severity level.

        Args:
            results: List of scan result dictionaries
            severity: Severity level to filter (CRITICAL or HIGH)

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

    def _send_message(self, content: str) -> None:
        """Send single message to Discord webhook.

        Args:
            content: Message content

        Raises:
            requests.HTTPError: If webhook request fails
        """
        payload = {"content": content}
        response = requests.post(
            self.webhook_url,
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
