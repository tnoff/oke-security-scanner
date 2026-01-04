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
        update_results: list[dict] | None = None,
        cleanup_recommendations: dict[str, dict] | None = None,
    ) -> bool:
        """Send formatted scan results to Discord.

        Args:
            scan_results: List of scan result dictionaries
            total_critical: Total count of critical vulnerabilities
            total_high: Total count of high vulnerabilities
            duration: Scan duration in seconds
            total_images: Total number of images scanned
            update_results: Optional list of image update results
            cleanup_recommendations: Optional dictionary of cleanup recommendations

        Returns:
            True if all messages sent successfully, False otherwise
        """
        try:
            # Count version updates
            minor_patch_count = 0
            major_count = 0
            if update_results:
                for result in update_results:
                    update_info = result.get("update_info")
                    if update_info:
                        if update_info["is_major_update"]:
                            major_count += 1
                        else:
                            minor_patch_count += 1

            # Generate CSV with all vulnerabilities, version updates, and cleanup recommendations
            csv_data = self._generate_csv(scan_results, update_results, cleanup_recommendations)

            # === MESSAGE BLOCK 1: Vulnerability Scan Results ===
            vuln_summary = (
                f"Security Scan Complete\n"
                f"Scanned: {total_images} images in {duration:.1f}s\n"
                f"Critical: {total_critical} | High: {total_high}"
            )

            # Build table for Critical vulnerabilities WITH fixes only
            critical_with_fixes_table = self._build_vulnerability_table(
                scan_results, "CRITICAL", only_with_fixes=True
            )

            # Combine vulnerability summary and critical table (may be paginated)
            vuln_messages = [vuln_summary]
            if critical_with_fixes_table:
                vuln_messages.extend(critical_with_fixes_table)

            # Send vulnerability messages with CSV attached to first message only
            for idx, message in enumerate(vuln_messages):
                is_first = idx == 0
                csv_file = csv_data if is_first else None

                logger.debug(
                    f"Sending vulnerability message {idx + 1}/{len(vuln_messages)} "
                    f"({len(message)} chars{', with CSV' if is_first else ''})"
                )
                self._send_message(message, csv_file=csv_file)

                # Add delay between messages to avoid rate limiting
                if idx < len(vuln_messages) - 1:
                    time.sleep(1)

            # === MESSAGE BLOCK 2: Version Update Results ===
            if update_results and (minor_patch_count > 0 or major_count > 0):
                # Add delay before sending update block
                time.sleep(1)

                update_summary = (
                    f"Image Version Updates\n"
                    f"Minor/Patch: {minor_patch_count} | Major: {major_count}\n"
                    f"(Major updates excluded below, see CSV for full report)"
                )

                # Build table for Minor/Patch version updates only
                update_table = self._build_update_table(update_results, only_minor_patch=True)

                # Combine update summary and table (may be paginated)
                update_messages = [update_summary]
                if update_table:
                    update_messages.extend(update_table)

                # Send update messages
                for idx, message in enumerate(update_messages):
                    logger.debug(
                        f"Sending update message {idx + 1}/{len(update_messages)} "
                        f"({len(message)} chars)"
                    )
                    self._send_message(message)

                    # Add delay between messages to avoid rate limiting
                    if idx < len(update_messages) - 1:
                        time.sleep(1)

            total_messages = len(vuln_messages) + (len(update_messages) if update_results else 0)
            logger.info(f"Successfully sent {total_messages} Discord message(s) with CSV attachment")
            return True

        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False

    def send_cleanup_recommendations(
        self, cleanup_recommendations: dict[str, dict]
    ) -> bool:
        """Send OCIR cleanup recommendations to Discord.

        Args:
            cleanup_recommendations: Dictionary of cleanup recommendations from RegistryClient

        Returns:
            True if message sent successfully, False otherwise
        """
        if not cleanup_recommendations:
            logger.debug("No cleanup recommendations to send")
            return True

        try:
            # Calculate totals
            total_repos = len(cleanup_recommendations)
            total_deletable = sum(r['total_deletable'] for r in cleanup_recommendations.values())

            # Build summary message
            summary = (
                f"OCIR Cleanup Recommendations\n"
                f"Repositories: {total_repos} | Deletable tags: {total_deletable}\n\n"
                f"Keep: Last 5 commit hash tags + tags in use\n"
                f"Safe to delete: Older commit hash tags"
            )

            # Build table with cleanup details
            table_messages = self._build_cleanup_table(cleanup_recommendations)

            # Combine summary and table (may be paginated)
            messages = [summary]
            if table_messages:
                messages.extend(table_messages)

            # Send all cleanup messages
            for idx, message in enumerate(messages):
                self._send_message(message)

                # Add delay between messages to avoid rate limiting
                if idx < len(messages) - 1:
                    time.sleep(1)

            logger.info(f"Successfully sent {len(messages)} cleanup recommendation message(s)")
            return True

        except Exception as e:
            logger.error(f"Failed to send cleanup recommendations: {e}")
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

    def _build_update_table(
        self, update_results: list[dict] | None, only_minor_patch: bool = False
    ) -> list[str]:
        """Build a table of version updates.

        Args:
            update_results: List of update result dictionaries
            only_minor_patch: If True, only include minor/patch updates

        Returns:
            List of message strings (paginated if needed)
        """
        if not update_results:
            return []

        # Define table headers with column widths
        headers = DapperTableHeaderOptions([
            DapperTableHeader("Image", 30),
            DapperTableHeader("Current", 15),
            DapperTableHeader("Latest", 15),
            DapperTableHeader("Type", 10),
        ])

        # Create table with headers and pagination
        table = DapperTable(
            header_options=headers,
            pagination_options=PaginationLength(self.max_length),
            prefix="Minor/Patch Updates Available:\n",
            enclosure_start="```",
            enclosure_end="```",
        )

        # Collect update rows
        rows = []
        for result in update_results:
            image = result.get("image", "unknown")
            update_info = result.get("update_info")

            if not update_info:
                continue

            # Skip major updates if only showing minor/patch
            if only_minor_patch and update_info["is_major_update"]:
                continue

            # Extract short image name
            short_name = image.split("/")[-1] if "/" in image else image

            current = update_info["current"]
            latest = update_info["latest"]

            # Determine update type
            if current.is_semver and latest.is_semver:
                if update_info["major_diff"] > 0:
                    update_type = "MAJOR"
                elif update_info["minor_diff"] > 0:
                    update_type = "minor"
                else:
                    update_type = "patch"
            else:
                update_type = "newer"

            rows.append([
                short_name,
                current.to_string()[:15],
                latest.to_string()[:15],
                update_type
            ])

        # Sort rows by image name
        rows.sort(key=lambda x: x[0])

        # Add rows to table
        for row in rows:
            table.add_row(row)

        # Return paginated messages
        if not rows:
            return []

        messages = table.print()
        if isinstance(messages, str):
            return [messages]
        return messages

    def _build_cleanup_table(self, cleanup_recommendations: dict[str, dict]) -> list[str]:
        """Build formatted table for cleanup recommendations.

        Args:
            cleanup_recommendations: Dictionary of cleanup recommendations

        Returns:
            List of formatted message strings (may be paginated)
        """
        if not cleanup_recommendations:
            return []

        # Define table headers with column widths
        headers = DapperTableHeaderOptions([
            DapperTableHeader("Repository", 40),
            DapperTableHeader("In Use", 10),
            DapperTableHeader("Keep", 10),
            DapperTableHeader("Delete", 10),
            DapperTableHeader("Oldest Tag (Age)", 20),
        ])

        # Create table with headers and pagination
        table = DapperTable(
            header_options=headers,
            pagination_options=PaginationLength(1800),
            prefix="OCIR Cleanup Candidates:\n",
            enclosure_start="```",
            enclosure_end="```",
        )

        # Collect cleanup rows
        for repo_key in sorted(cleanup_recommendations.keys()):
            rec = cleanup_recommendations[repo_key]
            repository = rec['repository']
            tags_in_use = rec['tags_in_use']
            tags_to_keep = rec['tags_to_keep']
            tags_to_delete = rec['tags_to_delete']

            # Find oldest tag
            oldest = "N/A"
            if tags_to_delete:
                # tags_to_delete is already sorted by age (newest first when created)
                # We want the last one (oldest)
                oldest_tag = tags_to_delete[-1]
                oldest = f"{oldest_tag['tag'][:7]} ({oldest_tag['age_days']}d)"

            table.add_row([
                repository,
                str(len(tags_in_use)),
                str(len(tags_to_keep)),
                str(len(tags_to_delete)),
                oldest
            ])

        messages = table.print()
        if isinstance(messages, str):
            return [messages]
        return messages

    def _generate_csv(
        self,
        results: list[dict],
        update_results: list[dict] | None = None,
        cleanup_recommendations: dict[str, dict] | None = None
    ) -> str:
        """Generate CSV data for all vulnerabilities, version updates, and cleanup recommendations.

        Args:
            results: List of scan result dictionaries
            update_results: Optional list of update result dictionaries
            cleanup_recommendations: Optional dictionary of cleanup recommendations

        Returns:
            CSV data as a string
        """
        output = StringIO()
        writer = csv.writer(output)

        # Section 1: Vulnerabilities
        writer.writerow(["=== VULNERABILITIES ==="])
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

        # Write vulnerability rows
        for row in rows:
            writer.writerow(row)

        # Section 2: Version Updates
        if update_results:
            writer.writerow([])  # Blank row separator
            writer.writerow(["=== VERSION UPDATES ==="])
            writer.writerow(["Image", "Current Version", "Latest Version", "Update Type", "Age (days)", "Version Diff"])

            update_rows = []
            for result in update_results:
                image = result.get("image", "unknown")
                update_info = result.get("update_info")

                if not update_info:
                    continue

                current = update_info["current"]
                latest = update_info["latest"]

                # Determine update type and diff
                if current.is_semver and latest.is_semver:
                    if update_info["is_major_update"]:
                        update_type = "MAJOR"
                    elif update_info["minor_diff"] > 0:
                        update_type = "Minor"
                    else:
                        update_type = "Patch"

                    version_diff = f"+{update_info['major_diff']}.{update_info['minor_diff']}.{update_info['patch_diff']}"
                else:
                    update_type = "Commit Hash"
                    version_diff = "N/A"

                # Get age information
                current_age = current.age_days() if current.created_at else "N/A"
                if current_age != "N/A":
                    age_str = str(current_age)
                else:
                    age_str = "N/A"

                update_rows.append([
                    image,
                    current.to_string(),
                    latest.to_string(),
                    update_type,
                    age_str,
                    version_diff
                ])

            # Sort by update type (MAJOR first), then image
            type_order = {"MAJOR": 0, "Minor": 1, "Patch": 2, "Commit Hash": 3}
            update_rows.sort(key=lambda x: (type_order.get(x[3], 99), x[0]))

            # Write update rows
            for row in update_rows:
                writer.writerow(row)

        # Section 3: Cleanup Recommendations
        if cleanup_recommendations:
            writer.writerow([])  # Blank row separator
            writer.writerow(["=== OCIR CLEANUP RECOMMENDATIONS ==="])
            writer.writerow(["Repository", "Tag", "Created Date", "Age (days)", "Status"])

            cleanup_rows = []
            for repo_key in sorted(cleanup_recommendations.keys()):
                rec = cleanup_recommendations[repo_key]
                repository = rec['repository']
                tags_in_use = rec['tags_in_use']
                tags_to_keep = rec['tags_to_keep']
                tags_to_delete = rec['tags_to_delete']

                # Add tags in use
                for tag in sorted(tags_in_use):
                    cleanup_rows.append([repository, tag, "N/A", "N/A", "In Use - Keep"])

                # Add recent tags to keep
                for tag in sorted(tags_to_keep):
                    cleanup_rows.append([repository, tag, "N/A", "N/A", "Recent - Keep"])

                # Add old tags recommended for deletion
                for tag_info in tags_to_delete:
                    tag = tag_info['tag']
                    created_at = tag_info['created_at']
                    age_days = tag_info['age_days']
                    created_str = created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
                    cleanup_rows.append([repository, tag, created_str, str(age_days), "Old - Can Delete"])

            # Write cleanup rows
            for row in cleanup_rows:
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
