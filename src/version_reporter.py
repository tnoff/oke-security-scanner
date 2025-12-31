"""Report generation for image version updates."""

from logging import getLogger
from typing import List, Dict, Any

logger = getLogger(__name__)


class VersionReporter:
    """Generates reports for image version updates."""

    @staticmethod
    def generate_report(update_results: List[Dict[str, Any]]) -> str:
        """Generate a formatted report for image version updates.

        Args:
            update_results: List of update check results with image and update info

        Returns:
            Formatted report string
        """
        if not update_results:
            return "\nNo version updates found.\n"

        # Split into major and non-major updates
        major_updates = []
        minor_updates = []

        for result in update_results:
            update_info = result.get("update_info")
            if update_info:
                if update_info["is_major_update"]:
                    major_updates.append(result)
                else:
                    minor_updates.append(result)

        # Build report
        lines = []
        lines.append("")
        lines.append("=" * 80)
        lines.append("Image Version Update Report")
        lines.append("=" * 80)

        # Summary
        total_updates = len(major_updates) + len(minor_updates)
        lines.append(f"Total images with updates available: {total_updates}")
        lines.append(f"  - MAJOR updates: {len(major_updates)}")
        lines.append(f"  - Minor/Patch updates: {len(minor_updates)}")
        lines.append("")

        # Major updates section
        if major_updates:
            lines.append("-" * 80)
            lines.append("MAJOR VERSION UPDATES (Breaking changes expected)")
            lines.append("-" * 80)
            for result in sorted(major_updates, key=lambda x: x["image"]):
                lines.append("")
                lines.extend(VersionReporter._format_update_entry(result))

        # Minor/Patch updates section
        if minor_updates:
            lines.append("")
            lines.append("-" * 80)
            lines.append("Minor/Patch Version Updates")
            lines.append("-" * 80)
            for result in sorted(minor_updates, key=lambda x: x["image"]):
                lines.append("")
                lines.extend(VersionReporter._format_update_entry(result))

        lines.append("")
        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _format_update_entry(result: Dict[str, Any]) -> List[str]:
        """Format a single update entry.

        Args:
            result: Update result dict with image and update info

        Returns:
            List of formatted lines
        """
        image = result["image"]
        update_info = result["update_info"]

        current = update_info["current"]
        latest = update_info["latest"]

        lines = []
        lines.append(f"Image:   {image}")

        # Format based on version type
        if current.is_semver and latest.is_semver:
            lines.append(f"Current: {current.to_string()} (tag: {current.tag})")
            lines.append(f"Latest:  {latest.to_string()} (tag: {latest.tag})")

            # Version differences
            major_diff = update_info["major_diff"]
            minor_diff = update_info["minor_diff"]
            patch_diff = update_info["patch_diff"]

            if major_diff > 0:
                lines.append(f"Change:  +{major_diff} major, +{minor_diff} minor, +{patch_diff} patch")
            elif minor_diff > 0:
                lines.append(f"Change:  +{minor_diff} minor, +{patch_diff} patch")
            else:
                lines.append(f"Change:  +{patch_diff} patch")

        else:
            # Non-semver (commit hash) comparison
            lines.append(f"Current: {current.tag}")
            lines.append(f"Latest:  {latest.tag}")

            if current.created_at and latest.created_at:
                current_age = current.age_days()
                latest_age = latest.age_days()
                age_diff = current_age - latest_age

                lines.append(f"Age:     Current is {current_age} days old, latest is {latest_age} days old")
                lines.append(f"Change:  Update is {age_diff} days newer")

        return lines

    @staticmethod
    def log_summary(update_results: List[Dict[str, Any]]) -> None:
        """Log a summary of update check results.

        Args:
            update_results: List of update check results
        """
        major_count = sum(
            1 for r in update_results
            if r.get("update_info") and r["update_info"]["is_major_update"]
        )
        minor_count = sum(
            1 for r in update_results
            if r.get("update_info") and not r["update_info"]["is_major_update"]
        )

        logger.info(f"Version check completed: {len(update_results)} images checked")
        if major_count > 0 or minor_count > 0:
            logger.info(f"  - {major_count} MAJOR updates available")
            logger.info(f"  - {minor_count} minor/patch updates available")
        else:
            logger.info("  - All images are up to date")
