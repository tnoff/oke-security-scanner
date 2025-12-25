"""Tests for discord_notifier module."""

import pytest
from unittest.mock import Mock, patch, call
from src.discord_notifier import DiscordNotifier


class TestDiscordNotifier:
    """Tests for DiscordNotifier class."""

    @pytest.fixture
    def notifier(self):
        """Create a DiscordNotifier instance."""
        return DiscordNotifier("https://discord.com/api/webhooks/test")

    @pytest.fixture
    def sample_scan_results(self):
        """Create sample scan results."""
        return [
            {
                "image": "iad.ocir.io/namespace/app1:latest",
                "cves": {
                    "CVE-2023-1234": {
                        "severity": "CRITICAL",
                        "title": "Critical vulnerability in package A",
                        "package": "packageA",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                    "CVE-2023-5678": {
                        "severity": "HIGH",
                        "title": "High severity issue in package B",
                        "package": "packageB",
                        "installed": "2.0.0",
                        "fixed": "2.0.1",
                    },
                },
            },
            {
                "image": "iad.ocir.io/namespace/app2:v1.0",
                "cves": {
                    "CVE-2023-1234": {
                        "severity": "CRITICAL",
                        "title": "Critical vulnerability in package A",
                        "package": "packageA",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                },
            },
        ]

    def test_init(self, notifier):
        """Test DiscordNotifier initialization."""
        assert notifier.webhook_url == "https://discord.com/api/webhooks/test"
        assert notifier.max_length == 2000

    def test_build_vulnerability_table(self, notifier, sample_scan_results):
        """Test _build_vulnerability_table method."""
        table_messages = notifier._build_vulnerability_table(sample_scan_results, "CRITICAL")

        assert len(table_messages) > 0
        # Should contain the severity header
        assert "CRITICAL Vulnerabilities" in table_messages[0]
        # Should contain table headers
        assert "Image" in table_messages[0]
        assert "CVE" in table_messages[0]
        assert "Fixed" in table_messages[0]
        # Should contain the CVE data
        assert "CVE-2023-1234" in table_messages[0]

    def test_build_vulnerability_table_with_fix(self, notifier):
        """Test that table shows fixed version when available."""
        results = [
            {
                "image": "test:latest",
                "cves": {
                    "CVE-2023-0000": {
                        "severity": "CRITICAL",
                        "title": "Some vulnerability",
                        "package": "pkg",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                },
            }
        ]

        table_messages = notifier._build_vulnerability_table(results, "CRITICAL")
        assert len(table_messages) > 0
        assert "CVE-2023-0000" in table_messages[0]
        assert "1.0.1" in table_messages[0]

    def test_build_vulnerability_table_without_fix(self, notifier):
        """Test that table shows 'No fix' when no fix available."""
        results = [
            {
                "image": "test:latest",
                "cves": {
                    "CVE-2023-0000": {
                        "severity": "CRITICAL",
                        "title": "Some vulnerability",
                        "package": "pkg",
                        "installed": "1.0.0",
                        "fixed": "",
                    },
                },
            }
        ]

        table_messages = notifier._build_vulnerability_table(results, "CRITICAL")
        assert len(table_messages) > 0
        assert "CVE-2023-0000" in table_messages[0]
        assert "No fix" in table_messages[0]

    def test_build_vulnerability_table_empty(self, notifier):
        """Test that empty table is handled correctly."""
        results = []
        table_messages = notifier._build_vulnerability_table(results, "CRITICAL")
        # Should still return messages with headers
        assert len(table_messages) > 0

    @patch('src.discord_notifier.requests.post')
    def test_send_message_success(self, mock_post, notifier):
        """Test successful message sending."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        notifier._send_message("Test message")

        mock_post.assert_called_once_with(
            "https://discord.com/api/webhooks/test",
            json={"content": "Test message"},
            timeout=10,
        )
        mock_response.raise_for_status.assert_called_once()

    @patch('src.discord_notifier.requests.post')
    def test_send_scan_report_success(self, mock_post, notifier, sample_scan_results):
        """Test send_scan_report successfully sends message."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        result = notifier.send_scan_report(
            scan_results=sample_scan_results,
            total_critical=1,
            total_high=1,
            duration=10.5,
            total_images=2,
        )

        assert result is True
        # Should send at least summary message + tables for critical and high
        assert mock_post.call_count >= 3

    @patch('src.discord_notifier.requests.post')
    def test_send_scan_report_handles_error(self, mock_post, notifier, sample_scan_results):
        """Test send_scan_report handles exceptions."""
        mock_post.side_effect = Exception("Network error")

        result = notifier.send_scan_report(
            scan_results=sample_scan_results,
            total_critical=1,
            total_high=1,
            duration=10.5,
            total_images=2,
        )

        assert result is False

    @patch('src.discord_notifier.time.sleep')
    @patch('src.discord_notifier.requests.post')
    def test_send_scan_report_uses_rate_limiting(
        self, mock_post, mock_sleep, notifier, sample_scan_results
    ):
        """Test that send_scan_report uses rate limiting between messages."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        result = notifier.send_scan_report(
            scan_results=sample_scan_results,
            total_critical=1,
            total_high=1,
            duration=10.5,
            total_images=2,
        )

        assert result is True
        # Should send multiple messages (summary + tables)
        assert mock_post.call_count >= 3
        # Should have rate limiting delays between messages
        assert mock_sleep.called
        # Number of delays should be one less than number of messages
        assert mock_sleep.call_count == mock_post.call_count - 1

    def test_extracts_short_image_names(self, notifier):
        """Test that image names are shortened (registry removed)."""
        results = [
            {
                "image": "iad.ocir.io/namespace/myapp:v1.0.0",
                "cves": {
                    "CVE-2023-1234": {
                        "severity": "CRITICAL",
                        "title": "Test",
                        "package": "pkg",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                },
            }
        ]

        table_messages = notifier._build_vulnerability_table(results, "CRITICAL")

        # Should show shortened name, not full path
        assert "myapp:v1.0.0" in table_messages[0]
        assert "iad.ocir.io" not in table_messages[0]
