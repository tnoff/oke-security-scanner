"""Tests for discord_notifier module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from src.k8s_client import Image, ImageVersion


class TestDiscordNotifier:
    """Tests for DiscordNotifier class."""

    @pytest.fixture
    def mock_dapper_table(self):
        """Mock DapperTable to avoid external dependency issues."""
        with patch('src.discord_notifier.DapperTable') as mock:
            mock_instance = MagicMock()
            mock_instance.print.return_value = ["Test message"]
            mock_instance.size = 1
            mock.return_value = mock_instance
            yield mock

    @pytest.fixture
    def notifier(self, mock_dapper_table):
        """Create a DiscordNotifier instance."""
        from src.discord_notifier import DiscordNotifier
        return DiscordNotifier("https://discord.com/api/webhooks/test")

    @patch('src.discord_notifier.requests.post')
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

    @patch('src.discord_notifier.requests.post')
    def test_send_version_update_info(self, mock_post, notifier, mock_dapper_table):
        """Test sending version update info."""
        from src.registry_client import UpdateInfo

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Create ImageVersion via Image parsing
        current_img = Image("test.ocir.io/namespace/app:v1.0.0")
        latest_img = Image("test.ocir.io/namespace/app:v2.0.0")

        update_info = [
            UpdateInfo(
                registry="test.ocir.io",
                repo_name="namespace/app",
                current=current_img.version,
                latest=latest_img.version,
            )
        ]

        notifier.send_version_update_info(update_info)

        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_version_update_info_empty(self, mock_post, notifier, mock_dapper_table):
        """Test sending empty version update info."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Set size to 0 to simulate empty table
        mock_dapper_table.return_value.size = 0

        notifier.send_version_update_info([])

        # Should still send a "no updates" message
        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_cleanup_recommendations(self, mock_post, notifier, mock_dapper_table):
        """Test sending cleanup recommendations."""
        from src.registry_client import CleanupRecommendation

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        img = Image(
            "test.ocir.io/namespace/app:old123",
            ocid="ocid1.image.1",
            created_at=datetime.now(timezone.utc)
        )
        recommendations = [
            CleanupRecommendation(
                registry="test.ocir.io",
                repository="namespace/app",
                tags_to_delete=[img],
            )
        ]

        notifier.send_cleanup_recommendations(recommendations)

        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_cleanup_recommendations_empty(self, mock_post, notifier, mock_dapper_table):
        """Test sending empty cleanup recommendations."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Set size to 0 to simulate empty table
        mock_dapper_table.return_value.size = 0

        notifier.send_cleanup_recommendations([])

        # Should still send a "no deletions needed" message
        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results(self, mock_post, notifier, mock_dapper_table):
        """Test sending deletion results."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        deleted_images = [
            Image("test.ocir.io/namespace/app:old1"),
            Image("test.ocir.io/namespace/app:old2"),
        ]

        notifier.send_deletion_results(deleted_images)

        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_empty(self, mock_post, notifier, mock_dapper_table):
        """Test sending empty deletion results."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Set size to 0 to simulate empty table
        mock_dapper_table.return_value.size = 0

        notifier.send_deletion_results([])

        # Should still send a "no images deleted" message
        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_node_image_report(self, mock_post, notifier, mock_dapper_table):
        """Test sending node image update report."""
        from src.oke_client import NodeImageUpdateInfo

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        updates = [
            NodeImageUpdateInfo(
                node_pool_name="pool-1",
                kubernetes_version="v1.28.2",
                current_image_name="Oracle-Linux-8.10-aarch64-2025.11.20-0",
                current_image_date=datetime(2025, 11, 20),
                latest_image_name="Oracle-Linux-8.10-aarch64-2025.12.15-0",
                latest_image_date=datetime(2025, 12, 15),
                latest_image_id="ocid1.image.oc1.test",
            )
        ]

        notifier.send_node_image_report(updates)

        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_node_image_report_empty(self, mock_post, notifier, mock_dapper_table):
        """Test sending empty node image report."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Set size to 0 to simulate empty table
        mock_dapper_table.return_value.size = 0

        notifier.send_node_image_report([])

        # Should still send an "up to date" message
        assert mock_post.call_count >= 1

    @patch('src.discord_notifier.requests.post')
    def test_send_node_image_report_with_none_dates(self, mock_post, notifier, mock_dapper_table):
        """Test sending node image report when dates are None."""
        from src.oke_client import NodeImageUpdateInfo

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        updates = [
            NodeImageUpdateInfo(
                node_pool_name="pool-1",
                kubernetes_version="v1.28.2",
                current_image_name="Unknown",
                current_image_date=None,
                latest_image_name="Unknown",
                latest_image_date=None,
                latest_image_id="ocid1.image.oc1.test",
            )
        ]

        notifier.send_node_image_report(updates)

        assert mock_post.call_count >= 1
