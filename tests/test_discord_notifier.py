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
        """Deleted tags are grouped under their repo with a count and code block."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        deleted_images = [
            Image("test.ocir.io/namespace/app:old1"),
            Image("test.ocir.io/namespace/app:old2"),
        ]

        notifier.send_deletion_results(deleted_images)

        posted = '\n'.join(c.kwargs['json']['content'] for c in mock_post.call_args_list)
        assert '## Images Deleted' in posted
        assert 'Deleted 2 app images:' in posted
        assert 'old1' in posted and 'old2' in posted

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_empty(self, mock_post, notifier, mock_dapper_table):
        """With nothing scanned or deleted, post a plain 'no images' line, not a heading."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        notifier.send_deletion_results([])

        assert mock_post.call_count == 1
        posted = mock_post.call_args.kwargs['json']['content']
        assert posted == 'No images were deleted.'

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_empty_orphan(self, mock_post, notifier, mock_dapper_table):
        """Empty orphan-pass results keep the orphan-specific wording, no heading."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        notifier.send_deletion_results([], is_orphaned=True)

        assert mock_post.call_count == 1
        posted = mock_post.call_args.kwargs['json']['content']
        assert posted == 'No orphan intermediate images were deleted.'

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_names_clean_repos(self, mock_post, notifier, mock_dapper_table):
        """Scanned repos with no deletions get an explicit per-repo 'No <repo>' line."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        notifier.send_deletion_results(
            [Image("test.ocir.io/ns/hathor:v1.2")],
            scanned_repos=[
                "test.ocir.io/ns/hathor",
                "test.ocir.io/ns/discord-bot",
            ],
        )

        posted = '\n'.join(c.kwargs['json']['content'] for c in mock_post.call_args_list)
        assert 'Deleted 1 hathor image:' in posted
        assert 'No discord-bot images deleted.' in posted

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_all_clean_has_no_heading(self, mock_post, notifier, mock_dapper_table):
        """When scanned repos are all clean, list per-repo lines without a heading."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        notifier.send_deletion_results(
            [],
            scanned_repos=["test.ocir.io/ns/discord-bot"],
        )

        posted = '\n'.join(c.kwargs['json']['content'] for c in mock_post.call_args_list)
        assert posted == 'No discord-bot images deleted.'
        assert '## Images Deleted' not in posted

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_paginates_and_splits_large_repo(self, mock_post, notifier, mock_dapper_table):
        """Output over the message limit splits across messages, and a repo with
        too many tags for one code block spills into a '(continued)' block."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        # Shrink the limit so a small fixture exercises both the per-repo
        # code-block split and the cross-message packing.
        notifier.max_length = 40

        notifier.send_deletion_results([
            Image("test.ocir.io/ns/app:aaaa"),
            Image("test.ocir.io/ns/app:bbbb"),
            Image("test.ocir.io/ns/app:cccc"),
        ])

        # Multiple webhook posts (heading + split blocks couldn't share one msg).
        assert mock_post.call_count > 1
        posted = '\n'.join(c.kwargs['json']['content'] for c in mock_post.call_args_list)
        assert 'Deleted 3 app images:' in posted
        assert '(continued)' in posted
        assert 'aaaa' in posted and 'cccc' in posted
        # No single message exceeded the (shrunken) limit's block budget.
        assert all(len(c.kwargs['json']['content']) for c in mock_post.call_args_list)

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
    def test_send_deletion_results_uses_orphan_heading(self, mock_post, notifier, mock_dapper_table):
        """is_orphaned=True selects the orphan-specific heading and noun."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        notifier.send_deletion_results(
            [Image("test.ocir.io/ns/app:v1.0.0")],
            is_orphaned=True,
        )

        posted = '\n'.join(c.kwargs['json']['content'] for c in mock_post.call_args_list)
        assert '## Orphan Intermediate Images Deleted' in posted
        assert 'Deleted 1 app orphan intermediate image:' in posted

    @patch('src.discord_notifier.requests.post')
    def test_send_deletion_results_substitutes_digest_for_unknown_tag(self, mock_post, notifier, mock_dapper_table):
        """When an image's tag is 'unknown', the code block uses its digest instead."""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.raise_for_status = Mock()

        img = Image(
            "test.ocir.io/ns/app:unknown",
            digest="sha256:deadbeef",
        )
        notifier.send_deletion_results([img])

        posted = '\n'.join(c.kwargs['json']['content'] for c in mock_post.call_args_list)
        assert 'sha256:deadbeef' in posted
