"""Tests for discord_notifier module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from src.k8s_client import Image


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
        mock_dapper_table.return_value.__len__.return_value = 0

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
        """Empty old-image cleanup results post the generic 'No Images Deleted' header."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Set size to 0 to simulate empty table
        mock_dapper_table.return_value.__len__.return_value = 0

        notifier.send_deletion_results([])

        assert mock_post.call_count == 1
        posted = mock_post.call_args.kwargs['json']['content']
        assert posted == '## No Images Deleted\n'

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_empty_orphan(self, mock_post, notifier, mock_dapper_table):
        """Empty orphan-pass results must keep the orphan-specific header, not collapse to the generic one."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        mock_dapper_table.return_value.__len__.return_value = 0

        notifier.send_deletion_results([], is_orphaned=True)

        assert mock_post.call_count == 1
        posted = mock_post.call_args.kwargs['json']['content']
        assert posted == '## No Orphan Intermediate Images Deleted\n'

    @patch('src.discord_notifier.requests.post')
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

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_uses_orphan_prefix(self, mock_post, notifier, mock_dapper_table):
        """is_orphaned=True selects the orphan-specific message prefix."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        notifier.send_deletion_results(
            [Image("test.ocir.io/ns/app:v1.0.0")],
            is_orphaned=True,
        )

        prefix_kwargs = [call.kwargs.get('prefix') for call in mock_dapper_table.call_args_list]
        assert any(p and 'Orphan' in p for p in prefix_kwargs)

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_substitutes_digest_for_unknown_tag(self, mock_post, notifier, mock_dapper_table):
        """When an image's tag is 'unknown', the row uses its digest instead."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        img = Image(
            "test.ocir.io/ns/app:unknown",
            digest="sha256:deadbeef",
        )
        notifier.send_deletion_results([img])

        rows_added = [call.args[0] for call in mock_dapper_table.return_value.add_row.call_args_list]
        assert ['test.ocir.io/ns/app', 'sha256:deadbeef'] in rows_added
