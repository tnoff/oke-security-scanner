"""Tests for scanner module."""

import json
import subprocess
import pytest
from unittest.mock import Mock, patch
from src.scanner import TrivyScanner, ScanResult, CVE, CVEDetails, CompleteScanResult
from src.k8s_client import Image


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    @pytest.fixture
    def config(self, base_config):
        """Use the shared base_config fixture."""
        return base_config

    @pytest.fixture
    def logger_provider(self):
        """Create mock logger provider."""
        return Mock()

    @pytest.fixture
    def scanner(self, config, logger_provider):
        """Create a TrivyScanner instance."""
        with patch('src.scanner.logger'):
            return TrivyScanner(config, logger_provider)

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
        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner._parse_vulnerabilities(image, sample_trivy_results)

        assert isinstance(result, ScanResult)
        assert result.critical_count == 1
        assert result.high_count == 1
        # critical_fixed_count and high_fixed_count track those with fixes
        assert result.critical_fixed_count == 1
        assert result.high_fixed_count == 1

    def test_parse_vulnerabilities_cves(self, scanner, sample_trivy_results):
        """Test _parse_vulnerabilities returns CVE details."""
        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner._parse_vulnerabilities(image, sample_trivy_results)

        # Find the critical CVE
        critical_cve = None
        for cve in result.cves:
            if cve.cve_id == "CVE-2023-1234":
                critical_cve = cve
                break

        assert critical_cve is not None
        assert len(critical_cve.details) == 1
        detail = critical_cve.details[0]
        assert detail.severity == "CRITICAL"
        assert detail.title == "Critical vulnerability in curl"
        assert detail.package == "curl"
        assert detail.installed == "7.68.0"
        assert detail.fixed == "7.68.1"

    def test_parse_vulnerabilities_empty_results(self, scanner):
        """Test _parse_vulnerabilities with empty results."""
        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner._parse_vulnerabilities(image, {})

        assert result is None

    def test_parse_vulnerabilities_no_results_key(self, scanner):
        """Test _parse_vulnerabilities with missing Results key."""
        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner._parse_vulnerabilities(image, {"SomeOtherKey": []})

        assert result is None

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

        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner.scan_image(image)

        assert result is not None
        assert isinstance(result, ScanResult)
        assert result.image == image
        assert result.critical_count == 1
        assert result.high_count == 1
        assert len(result.cves) == 3  # 3 unique CVEs

    @patch('src.scanner.subprocess.run')
    def test_scan_image_timeout(self, mock_run, scanner):
        """Test image scan timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 300)

        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner.scan_image(image)

        assert result is None

    @patch('src.scanner.subprocess.run')
    def test_scan_image_process_error(self, mock_run, scanner):
        """Test image scan process error."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "trivy", stderr="Scan failed"
        )

        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner.scan_image(image)

        assert result is None

    @patch('src.scanner.subprocess.run')
    def test_scan_image_json_decode_error(self, mock_run, scanner):
        """Test image scan with invalid JSON."""
        mock_result = Mock()
        mock_result.stdout = "not valid json"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        image = Image("test.ocir.io/namespace/app:v1.0.0")
        result = scanner.scan_image(image)

        assert result is None

    @patch('src.scanner.subprocess.run')
    def test_scan_image_command_includes_severity(self, mock_run, scanner, sample_trivy_results):
        """Test that scan command includes severity filter."""
        mock_result = Mock()
        mock_result.stdout = json.dumps(sample_trivy_results)
        mock_run.return_value = mock_result

        image = Image("test.ocir.io/namespace/app:v1.0.0")
        scanner.scan_image(image)

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

        image = Image("test.ocir.io/namespace/app:v1.0.0")
        scanner.scan_image(image)

        # Check the command includes timeout flag
        call_args = mock_run.call_args[0][0]
        assert "--timeout" in call_args
        assert "300s" in call_args


class TestCompleteScanResult:
    """Tests for CompleteScanResult dataclass."""

    def test_add_result_success(self):
        """Test adding a successful scan result."""
        complete = CompleteScanResult()
        image = Image("test.ocir.io/namespace/app:v1.0.0")
        scan_result = ScanResult(image)
        scan_result.critical_count = 2
        scan_result.critical_fixed_count = 1
        scan_result.high_count = 3
        scan_result.high_fixed_count = 2

        complete.add_result(scan_result)

        assert complete.total_critical == 2
        assert complete.total_critical_fixed == 1
        assert complete.total_high == 3
        assert complete.total_high_fixed == 2
        assert complete.failed_scans == 0
        assert len(complete.scan_results) == 1

    def test_add_result_none(self):
        """Test adding a None result (failed scan)."""
        complete = CompleteScanResult()

        complete.add_result(None)

        assert complete.failed_scans == 1
        assert complete.total_critical == 0
        assert len(complete.scan_results) == 0

    def test_multiple_results(self):
        """Test adding multiple scan results."""
        complete = CompleteScanResult()

        image1 = Image("test.ocir.io/namespace/app1:v1.0.0")
        result1 = ScanResult(image1)
        result1.critical_count = 2
        result1.high_count = 1

        image2 = Image("test.ocir.io/namespace/app2:v1.0.0")
        result2 = ScanResult(image2)
        result2.critical_count = 1
        result2.high_count = 2

        complete.add_result(result1)
        complete.add_result(result2)
        complete.add_result(None)  # Failed scan

        assert complete.total_critical == 3
        assert complete.total_high == 3
        assert complete.failed_scans == 1
        assert len(complete.scan_results) == 2
