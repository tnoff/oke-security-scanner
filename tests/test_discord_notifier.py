"""Tests for discord_notifier module."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from oke_scanner_core.image import Image


class TestDiscordNotifier:
    """Tests for DiscordNotifier class."""

    @pytest.fixture
    def mock_dapper_table(self):
        """Mock DapperTable to avoid external dependency issues."""
        with patch('src.discord_notifier.DapperTable') as mock:
            mock_instance = MagicMock()
            mock_instance.render.return_value = ["Test message"]
            mock_instance.__len__.return_value = 1
            mock.return_value = mock_instance
            yield mock

    @pytest.fixture
    def notifier(self, mock_dapper_table):
        """Create a DiscordNotifier instance."""
        from src.discord_notifier import DiscordNotifier
        return DiscordNotifier("https://discord.com/api/webhooks/test")

    @patch('oke_scanner_core.discord_webhook.requests.post')
    def test_send_image_scan_report(self, mock_post, notifier, mock_dapper_table):
        """Test sending image scan report."""
        from src.scanner import CompleteScanResult, ScanResult, CVE, CVEDetails

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Create a scan result
        image = Image("test.ocir.io/namespace/app:v1.0.0")
        scan_result = ScanResult(image)
        scan_result.critical_count = 1
        scan_result.critical_fixed_count = 1
        scan_result.high_count = 2
        scan_result.high_fixed_count = 1
        scan_result.cves = [
            CVE("CVE-2023-1234", details=[
                CVEDetails("CRITICAL", "Test vuln", "curl", "7.0", "7.1")
            ])
        ]

        complete = CompleteScanResult()
        complete.add_result(scan_result)

        notifier.send_image_scan_report(complete)

        # Should have sent at least one message
        assert mock_post.call_count >= 1

    @patch('oke_scanner_core.discord_webhook.requests.post')
    def test_send_image_scan_report_shortens_dockerhub_failed_image(self, mock_post, notifier, mock_dapper_table):
        """Failed-scan rows for docker.io images use the short repo name (no 'docker.io/' prefix)."""
        from src.scanner import CompleteScanResult

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        complete = CompleteScanResult()
        complete.add_result(None, image=Image("docker.io/library/nginx:1.27"))
        complete.add_result(None, image=Image("iad.ocir.io/ns/app:v1.0.0"))

        notifier.send_image_scan_report(complete)

        rows_added = [call.args[0] for call in mock_dapper_table.return_value.add_row.call_args_list]
        # docker.io image rendered without registry prefix
        assert ['library/nginx:1.27'] in rows_added
        # Non-docker.io image keeps its registry prefix
        assert ['iad.ocir.io/ns/app:v1.0.0'] in rows_added
