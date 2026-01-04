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
        """Test successful message sending without file."""
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
    def test_send_message_with_csv(self, mock_post, notifier):
        """Test successful message sending with CSV attachment."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        csv_content = "Image,CVE,Severity,Fixed\ntest:latest,CVE-2023-1234,CRITICAL,1.0.1"
        notifier._send_message("Test message", csv_file=csv_content)

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args.kwargs["data"] == {"content": "Test message"}
        assert "file" in call_args.kwargs["files"]
        assert call_args.kwargs["files"]["file"][0] == "vulnerabilities.csv"
        assert call_args.kwargs["files"]["file"][1] == csv_content
        assert call_args.kwargs["files"]["file"][2] == "text/csv"
        mock_response.raise_for_status.assert_called_once()

    @patch('src.discord_notifier.time.sleep')
    @patch('src.discord_notifier.requests.post')
    def test_send_scan_report_success(self, mock_post, mock_sleep, notifier, sample_scan_results):
        """Test send_scan_report successfully sends message(s) with CSV attachment."""
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
        # Should send at least one message
        assert mock_post.call_count >= 1
        # First message should have CSV attachment
        first_call = mock_post.call_args_list[0]
        assert "files" in first_call.kwargs
        assert "file" in first_call.kwargs["files"]
        # Verify the first message content includes summary
        assert "Security Scan Complete" in first_call.kwargs["data"]["content"]
        assert "2 images" in first_call.kwargs["data"]["content"]
        # If multiple messages sent, verify rate limiting was used
        if mock_post.call_count > 1:
            assert mock_sleep.call_count == mock_post.call_count - 1

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

    def test_build_vulnerability_table_only_with_fixes(self, notifier):
        """Test that only_with_fixes filter works correctly."""
        results = [
            {
                "image": "test:latest",
                "cves": {
                    "CVE-2023-0001": {
                        "severity": "CRITICAL",
                        "title": "Has fix",
                        "package": "pkg1",
                        "installed": "1.0.0",
                        "fixed": "1.0.1",
                    },
                    "CVE-2023-0002": {
                        "severity": "CRITICAL",
                        "title": "No fix",
                        "package": "pkg2",
                        "installed": "2.0.0",
                        "fixed": "",
                    },
                },
            }
        ]

        table_messages = notifier._build_vulnerability_table(results, "CRITICAL", only_with_fixes=True)
        # Should only include CVE with fix
        assert "CVE-2023-0001" in table_messages[0]
        assert "CVE-2023-0002" not in table_messages[0]

    def test_generate_csv(self, notifier, sample_scan_results):
        """Test CSV generation includes all vulnerabilities."""
        csv_data = notifier._generate_csv(sample_scan_results)

        # Verify CSV header
        assert "Image,CVE,Severity,Fixed Version" in csv_data
        # Verify critical vulnerabilities are included
        assert "CVE-2023-1234" in csv_data
        assert "CRITICAL" in csv_data
        # Verify high vulnerabilities are included
        assert "CVE-2023-5678" in csv_data
        assert "HIGH" in csv_data
        # Verify images are included
        assert "iad.ocir.io/namespace/app1:latest" in csv_data
        assert "iad.ocir.io/namespace/app2:v1.0" in csv_data

    def test_generate_csv_sorted_by_severity(self, notifier):
        """Test that CSV rows are sorted by severity."""
        results = [
            {
                "image": "test:latest",
                "cves": {
                    "CVE-2023-0001": {
                        "severity": "HIGH",
                        "fixed": "1.0.1",
                    },
                    "CVE-2023-0002": {
                        "severity": "CRITICAL",
                        "fixed": "2.0.1",
                    },
                    "CVE-2023-0003": {
                        "severity": "MEDIUM",
                        "fixed": "",
                    },
                },
            }
        ]

        csv_data = notifier._generate_csv(results)
        lines = csv_data.strip().split("\n")

        # Skip section header and column header, check order: CRITICAL, HIGH, MEDIUM
        # Line 0: "=== VULNERABILITIES ==="
        # Line 1: "Image,CVE,Severity,Fixed Version"
        # Line 2+: Data rows
        assert "CRITICAL" in lines[2]
        assert "HIGH" in lines[3]
        assert "MEDIUM" in lines[4]

    def test_generate_csv_with_cleanup_recommendations(self, notifier, sample_scan_results):
        """Test CSV generation includes cleanup recommendations section."""
        from datetime import datetime, timezone

        cleanup_recommendations = {
            'test.ocir.io/namespace/myapp': {
                'registry': 'test.ocir.io',
                'repository': 'namespace/myapp',
                'tags_in_use': ['commit0', 'commit1'],
                'tags_to_keep': ['commit2', 'commit3', 'commit4'],
                'tags_to_delete': [
                    {
                        'tag': 'commit5',
                        'created_at': datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                        'age_days': 365
                    },
                    {
                        'tag': 'commit6',
                        'created_at': datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
                        'age_days': 200
                    },
                ],
                'total_deletable': 2
            }
        }

        csv_data = notifier._generate_csv(
            sample_scan_results,
            update_results=None,
            cleanup_recommendations=cleanup_recommendations
        )

        # Verify cleanup section header
        assert "=== OCIR CLEANUP RECOMMENDATIONS ===" in csv_data
        assert "Repository,Tag,Created Date,Age (days),Status" in csv_data

        # Verify tags in use
        assert "commit0" in csv_data
        assert "commit1" in csv_data
        assert "In Use - Keep" in csv_data

        # Verify tags to keep
        assert "commit2" in csv_data
        assert "commit3" in csv_data
        assert "commit4" in csv_data
        assert "Recent - Keep" in csv_data

        # Verify tags to delete
        assert "commit5" in csv_data
        assert "commit6" in csv_data
        assert "Old - Can Delete" in csv_data
        assert "2024-01-01 12:00:00 UTC" in csv_data
        assert "365" in csv_data
        assert "200" in csv_data

    def test_generate_csv_without_cleanup_recommendations(self, notifier, sample_scan_results):
        """Test CSV generation without cleanup recommendations."""
        csv_data = notifier._generate_csv(
            sample_scan_results,
            update_results=None,
            cleanup_recommendations=None
        )

        # Verify cleanup section is NOT included
        assert "=== OCIR CLEANUP RECOMMENDATIONS ===" not in csv_data
        assert "Old - Can Delete" not in csv_data
