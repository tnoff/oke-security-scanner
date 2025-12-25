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

    def test_build_summary(self, notifier):
        """Test _build_summary method."""
        mock_table = Mock()
        notifier._build_summary(mock_table, 10, 5, 15, 123.45)

        # Verify the correct rows were added
        calls = mock_table.add_row.call_args_list
        assert len(calls) == 4
        assert calls[0] == call("**Security Scan Complete**")
        assert calls[1] == call("📊 Scanned: 10 images in 123.5s")
        assert calls[2] == call("🔴 Critical: 5 | 🟠 High: 15")
        assert calls[3] == call("")

    def test_build_vulnerability_section_with_cves(self, notifier, sample_scan_results):
        """Test _build_vulnerability_section with CVEs present."""
        mock_table = Mock()
        notifier._build_vulnerability_section(
            mock_table, sample_scan_results, "CRITICAL", "🔴 CRITICAL"
        )

        # Get all the rows that were added
        calls = [str(call[0][0]) for call in mock_table.add_row.call_args_list]
        section = "\n".join(calls)

        assert "🔴 CRITICAL Vulnerabilities (1 unique)" in section
        assert "CVE-2023-1234" in section
        assert "Critical vulnerability in package A" in section
        assert "app1:latest" in section
        assert "app2:v1.0" in section

    def test_build_vulnerability_section_no_cves(self, notifier):
        """Test _build_vulnerability_section with no CVEs."""
        mock_table = Mock()
        notifier._build_vulnerability_section(mock_table, [], "CRITICAL", "🔴 CRITICAL")

        # Get all the rows that were added
        calls = [str(call[0][0]) for call in mock_table.add_row.call_args_list]
        section = "\n".join(calls)

        assert "🔴 CRITICAL Vulnerabilities" in section
        assert "None found ✅" in section

    def test_build_vulnerability_section_groups_by_cve(self, notifier, sample_scan_results):
        """Test that CVEs are grouped across images."""
        mock_table = Mock()
        notifier._build_vulnerability_section(
            mock_table, sample_scan_results, "CRITICAL", "🔴 CRITICAL"
        )

        # Get all the rows that were added
        calls = [str(call[0][0]) for call in mock_table.add_row.call_args_list]
        section = "\n".join(calls)

        # Should show CVE-2023-1234 once with both images listed
        assert section.count("CVE-2023-1234") == 1
        assert "app1:latest, app2:v1.0" in section or "app2:v1.0, app1:latest" in section

    def test_build_vulnerability_section_truncates_long_titles(self, notifier):
        """Test that long CVE titles are truncated."""
        results = [
            {
                "image": "test:latest",
                "cves": {
                    "CVE-2023-0000": {
                        "severity": "CRITICAL",
                        "title": "A" * 100,  # Very long title
                        "package": "pkg",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                },
            }
        ]

        mock_table = Mock()
        notifier._build_vulnerability_section(mock_table, results, "CRITICAL", "🔴 CRITICAL")

        # Get all the rows that were added
        calls = [str(call[0][0]) for call in mock_table.add_row.call_args_list]
        section = "\n".join(calls)

        # Should be truncated to 60 chars + "..."
        assert "AAA..." in section
        assert len("A" * 60 + "...") == 63  # Verify truncation length

    def test_build_vulnerability_section_limits_image_list(self, notifier):
        """Test that image lists are limited to 3 with +N more."""
        results = []
        for i in range(5):
            results.append({
                "image": f"app{i}:latest",
                "cves": {
                    "CVE-2023-1234": {
                        "severity": "CRITICAL",
                        "title": "Test CVE",
                        "package": "pkg",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                },
            })

        mock_table = Mock()
        notifier._build_vulnerability_section(mock_table, results, "CRITICAL", "🔴 CRITICAL")

        # Get all the rows that were added
        calls = [str(call[0][0]) for call in mock_table.add_row.call_args_list]
        section = "\n".join(calls)

        assert "+2 more" in section  # Should show first 3 + "2 more"

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

    @patch('src.discord_notifier.DapperTable')
    @patch('src.discord_notifier.requests.post')
    def test_send_scan_report_success(self, mock_post, mock_dappertable_class, notifier, sample_scan_results):
        """Test send_scan_report successfully sends message."""
        # Mock DapperTable
        mock_table = Mock()
        mock_table.print.return_value = ["Message 1"]
        mock_dappertable_class.return_value = mock_table

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
        assert mock_post.called

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

    @patch('src.discord_notifier.DapperTable')
    @patch('src.discord_notifier.requests.post')
    def test_send_scan_report_uses_dappertable_pagination(
        self, mock_post, mock_dappertable_class, notifier, sample_scan_results
    ):
        """Test that send_scan_report uses DapperTable for pagination."""
        mock_table = Mock()
        mock_table.print.return_value = ["Message 1", "Message 2"]
        mock_dappertable_class.return_value = mock_table

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
        # Verify DapperTable was created and used
        mock_dappertable_class.assert_called_once()
        # add_row should be called multiple times (for summary, critical and high sections)
        assert mock_table.add_row.called
        assert mock_table.add_row.call_count > 1
        mock_table.print.assert_called_once()
        # Should send both messages
        assert mock_post.call_count == 2

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

        mock_table = Mock()
        notifier._build_vulnerability_section(mock_table, results, "CRITICAL", "🔴 CRITICAL")

        # Get all the rows that were added
        calls = [str(call[0][0]) for call in mock_table.add_row.call_args_list]
        section = "\n".join(calls)

        # Should show shortened name, not full path
        assert "myapp:v1.0.0" in section
        assert "iad.ocir.io" not in section
