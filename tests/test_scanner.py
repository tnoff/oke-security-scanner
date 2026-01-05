"""Tests for scanner module."""

import json
import subprocess
import pytest
from unittest.mock import Mock, patch, MagicMock
from src.scanner import TrivyScanner
from src.config import Config


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        return Config(
            oci_registry="test.ocir.io",
            oci_username="testuser",
            oci_token="testtoken",
            oci_namespace="testnamespace",
            otlp_endpoint="http://localhost:4318",
            otlp_insecure=True,
            otlp_traces_enabled=True,
            otlp_metrics_enabled=True,
            otlp_logs_enabled=True,
            trivy_severity="CRITICAL,HIGH",
            trivy_timeout=300,
            namespaces=[],
            exclude_namespaces=["kube-system"],
            discord_webhook_url="",
            ocir_cleanup_enabled=False,
            ocir_cleanup_keep_count=5,
        )

    @pytest.fixture
    def metrics(self):
        """Create mock metrics."""
        return {
            "scan_total": Mock(),
        }

    @pytest.fixture
    def logger_provider(self):
        """Create mock logger provider."""
        return Mock()

    @pytest.fixture
    def scanner(self, config, metrics, logger_provider):
        """Create a TrivyScanner instance."""
        with patch('src.scanner.Path'), \
             patch('src.scanner.open'), \
             patch('src.scanner.json.dump'), \
             patch('src.scanner.logger'):
            return TrivyScanner(config, metrics, logger_provider)

    @pytest.fixture
    def sample_trivy_results(self):
        """Sample Trivy scan results."""
        return {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Severity": "CRITICAL",
                            "PkgName": "curl",
                            "InstalledVersion": "7.68.0",
                            "FixedVersion": "7.68.1",
                            "Title": "Critical vulnerability in curl",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-5678",
                            "Severity": "HIGH",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.2",
                            "Title": "High severity issue in openssl",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-9999",
                            "Severity": "MEDIUM",
                            "PkgName": "zlib",
                            "InstalledVersion": "1.2.11",
                            "FixedVersion": "1.2.12",
                            "Title": "Medium severity issue",
                        },
                    ]
                }
            ]
        }

    def test_parse_vulnerabilities_counts(self, scanner, sample_trivy_results):
        """Test _parse_vulnerabilities returns correct counts."""
        result = scanner._parse_vulnerabilities(sample_trivy_results)

        assert result["counts"]["CRITICAL"] == 1
        assert result["counts"]["HIGH"] == 1
        assert result["counts"]["MEDIUM"] == 1
        assert result["counts"]["LOW"] == 0

    def test_parse_vulnerabilities_cves(self, scanner, sample_trivy_results):
        """Test _parse_vulnerabilities returns CVE details."""
        result = scanner._parse_vulnerabilities(sample_trivy_results)

        assert "CVE-2023-1234" in result["cves"]
        assert result["cves"]["CVE-2023-1234"]["severity"] == "CRITICAL"
        assert result["cves"]["CVE-2023-1234"]["title"] == "Critical vulnerability in curl"
        assert result["cves"]["CVE-2023-1234"]["package"] == "curl"
        assert result["cves"]["CVE-2023-1234"]["installed"] == "7.68.0"
        assert result["cves"]["CVE-2023-1234"]["fixed"] == "7.68.1"

    def test_parse_vulnerabilities_empty_results(self, scanner):
        """Test _parse_vulnerabilities with empty results."""
        result = scanner._parse_vulnerabilities({})

        assert result["counts"]["CRITICAL"] == 0
        assert result["counts"]["HIGH"] == 0
        assert result["cves"] == {}

    def test_parse_vulnerabilities_no_results_key(self, scanner):
        """Test _parse_vulnerabilities with missing Results key."""
        result = scanner._parse_vulnerabilities({"SomeOtherKey": []})

        assert result["counts"]["CRITICAL"] == 0
        assert result["cves"] == {}

    @patch('src.scanner.subprocess.run')
    def test_update_database_success(self, mock_run, scanner):
        """Test successful database update."""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        result = scanner.update_database()

        assert result is True
        assert scanner.db_updated is True
        mock_run.assert_called_once()

    @patch('src.scanner.subprocess.run')
    def test_update_database_timeout(self, mock_run, scanner):
        """Test database update timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 120)

        result = scanner.update_database()

        assert result is False
        assert scanner.db_updated is False

    @patch('src.scanner.subprocess.run')
    def test_update_database_error(self, mock_run, scanner):
        """Test database update error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "trivy", stderr="Error updating database"
        )

        result = scanner.update_database()

        assert result is False

    @patch('src.scanner.subprocess.run')
    def test_scan_image_success(self, mock_run, scanner, sample_trivy_results):
        """Test successful image scan."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(sample_trivy_results)
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = scanner.scan_image("test-image:latest")

        assert result is not None
        assert result["image"] == "test-image:latest"
        assert "vulnerabilities" in result
        assert "cves" in result
        assert result["vulnerabilities"]["CRITICAL"] == 1
        assert result["vulnerabilities"]["HIGH"] == 1
        assert "CVE-2023-1234" in result["cves"]

    @patch('src.scanner.subprocess.run')
    def test_scan_image_timeout(self, mock_run, scanner):
        """Test image scan timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 300)

        result = scanner.scan_image("test-image:latest")

        assert result is None

    @patch('src.scanner.subprocess.run')
    def test_scan_image_process_error(self, mock_run, scanner):
        """Test image scan process error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "trivy", stderr="Scan failed"
        )

        result = scanner.scan_image("test-image:latest")

        assert result is None

    @patch('src.scanner.subprocess.run')
    def test_scan_image_json_decode_error(self, mock_run, scanner):
        """Test image scan with invalid JSON."""
        mock_result = Mock()
        mock_result.stdout = "not valid json"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = scanner.scan_image("test-image:latest")

        assert result is None

    @patch('src.scanner.subprocess.run')
    def test_scan_image_sets_metrics(self, mock_run, scanner, sample_trivy_results):
        """Test that scan_image sets metrics correctly."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(sample_trivy_results)
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = scanner.scan_image("test-image:latest")

        assert result is not None
        # Verify metrics were set
        assert scanner.metrics["scan_total"].set.call_count == 2  # Once for CRITICAL, once for HIGH

    @patch('src.scanner.subprocess.run')
    def test_scan_image_command_includes_severity(self, mock_run, scanner, sample_trivy_results):
        """Test that scan command includes severity filter."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(sample_trivy_results)
        mock_run.return_value = mock_result

        scanner.scan_image("test-image:latest")

        # Check the command includes severity flag
        call_args = mock_run.call_args[0][0]
        assert "--severity" in call_args
        assert "CRITICAL,HIGH" in call_args

    @patch('src.scanner.subprocess.run')
    def test_scan_image_command_includes_timeout(self, mock_run, scanner, sample_trivy_results):
        """Test that scan command includes timeout."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(sample_trivy_results)
        mock_run.return_value = mock_result

        scanner.scan_image("test-image:latest")

        # Check the command includes timeout flag
        call_args = mock_run.call_args[0][0]
        assert "--timeout" in call_args
        assert "300s" in call_args
