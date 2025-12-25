"""Discord webhook notification for scan results."""

from logging import getLogger

from dappertable import DapperTable, PaginationLength
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
            # Build complete message content
            summary = self._build_summary(total_images, total_critical, total_high, duration)
            critical_section = self._build_vulnerability_section(scan_results, "CRITICAL", "🔴 CRITICAL")
            high_section = self._build_vulnerability_section(scan_results, "HIGH", "🟠 HIGH")

            # Combine all sections
            full_content = summary + critical_section + high_section

            # Use dappertable to handle pagination at Discord's 2000 char limit
            # No header_options = no table headers, just paginated text
            table = DapperTable(
                pagination_options=PaginationLength(self.max_length),
            )
            # Add the full content as a single row
            table.add_row([full_content])

            # Get paginated messages
            messages = table.print()
            if isinstance(messages, str):
                messages = [messages]

            # Send each message
            for idx, msg in enumerate(messages, 1):
                logger.debug(f"Sending Discord message {idx}/{len(messages)} ({len(msg)} chars)")
                self._send_message(msg)

            logger.info(f"Successfully sent {len(messages)} Discord message(s)")
            return True

        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False

    def _build_summary(
        self, total_images: int, critical: int, high: int, duration: float
    ) -> str:
        """Build scan summary header.

        Args:
            total_images: Number of images scanned
            critical: Critical vulnerability count
            high: High vulnerability count
            duration: Scan duration in seconds

        Returns:
            Formatted summary string
        """
        return f"""**Security Scan Complete**
📊 Scanned: {total_images} images in {duration:.1f}s
🔴 Critical: {critical} | 🟠 High: {high}
"""

    def _build_vulnerability_section(
        self, results: list[dict], severity: str, emoji_header: str
    ) -> str:
        """Build section for specific severity level.

        Args:
            results: List of scan result dictionaries
            severity: Severity level to filter (CRITICAL or HIGH)
            emoji_header: Header text with emoji

        Returns:
            Formatted vulnerability section string
        """
        # Group by CVE
        cve_to_images: dict[str, dict] = {}

        for result in results:
            image = result.get("image", "unknown")
            cves = result.get("cves", {})

            for cve_id, details in cves.items():
                if details.get("severity") == severity:
                    if cve_id not in cve_to_images:
                        cve_to_images[cve_id] = {
                            "title": details.get("title", ""),
                            "images": set(),
                        }
                    # Extract short image name (remove registry prefix)
                    short_name = image.split("/")[-1] if "/" in image else image
                    cve_to_images[cve_id]["images"].add(short_name)

        if not cve_to_images:
            return f"\n**{emoji_header} Vulnerabilities**\nNone found ✅\n"

        # Format output
        lines = [f"\n**{emoji_header} Vulnerabilities ({len(cve_to_images)} unique)**"]

        for cve_id, data in sorted(cve_to_images.items()):
            # Truncate long titles
            title = data["title"]
            title_short = title[:60] + "..." if len(title) > 60 else title

            # Show up to 3 images, then count remaining
            images_list = sorted(data["images"])
            images_str = ", ".join(images_list[:3])
            if len(images_list) > 3:
                images_str += f" +{len(images_list) - 3} more"

            lines.append(f"• **{cve_id}**: {title_short}")
            lines.append(f"  Affects: {images_str}")

        return "\n".join(lines)

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
