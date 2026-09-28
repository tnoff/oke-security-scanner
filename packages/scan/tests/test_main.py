"""Tests for main module."""

import pytest
from unittest.mock import Mock, patch
from scan.main import main, setup_otel, send_scan_metrics


class TestSetupOtel:
    """Tests for setup_otel function."""

    @patch('scan.main.setup_telemetry')
    @patch('scan.main.create_metrics')
    def test_setup_otel_with_all_providers(self, mock_create_metrics, mock_setup_telemetry, base_config):
        """Test setup_otel with all providers enabled."""
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (mock_meter_provider, mock_logger_provider)

        mock_metrics = Mock()
        mock_create_metrics.return_value = mock_metrics

        meter_provider, logger_provider, metrics = setup_otel(base_config)

        assert meter_provider == mock_meter_provider
        assert logger_provider == mock_logger_provider
        assert metrics == mock_metrics

    @patch('scan.main.setup_telemetry')
    @patch('scan.main.create_metrics')
    def test_setup_otel_with_no_providers(self, mock_create_metrics, mock_setup_telemetry, base_config):
        """Test setup_otel when all providers are disabled."""
        mock_setup_telemetry.return_value = (None, None)
        mock_create_metrics.return_value = None

        meter_provider, logger_provider, metrics = setup_otel(base_config)

        assert meter_provider is None
        assert logger_provider is None
        assert metrics is None


class TestMain:
    """Tests for main function."""

    @patch('scan.main.DiscordNotifier')
    @patch('scan.main.logging')
    @patch('scan.main.Config')
    @patch('scan.main.setup_telemetry')
    @patch('scan.main.create_metrics')
    @patch('scan.main.TrivyScanner')
    @patch('scan.main.KubernetesClient')
    def test_main_successful_run(
        self,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord,
    ):
        """Test main successful run."""
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        mock_meter_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (mock_meter_provider, mock_logger_provider)
        mock_create_metrics.return_value = None

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        main()

        # Should flush telemetry
        mock_meter_provider.force_flush.assert_called_once()
        mock_logger_provider.force_flush.assert_called_once()

    @patch('scan.main.DiscordNotifier')
    @patch('scan.main.logging')
    @patch('scan.main.Config')
    @patch('scan.main.setup_telemetry')
    @patch('scan.main.create_metrics')
    @patch('scan.main.TrivyScanner')
    @patch('scan.main.KubernetesClient')
    def test_main_with_discord_notification(
        self,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord,
    ):
        """Test main sends Discord notification when URL is configured."""
        mock_config = Mock()
        mock_config.discord_webhook_url = "https://discord.com/webhook"
        mock_config_class.from_env.return_value = mock_config

        mock_setup_telemetry.return_value = (None, None)
        mock_create_metrics.return_value = None

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        mock_k8s_instance = Mock()
        from oke_scanner_core.image import Image
        mock_k8s_instance.get_all_images.return_value = {Image("test.ocir.io/ns/app:v1")}
        mock_k8s_client.return_value = mock_k8s_instance

        main()

        mock_discord.assert_called()

    @patch('scan.main.DiscordNotifier')
    @patch('scan.main.logging')
    @patch('scan.main.Config')
    @patch('scan.main.setup_telemetry')
    @patch('scan.main.create_metrics')
    @patch('scan.main.TrivyScanner')
    @patch('scan.main.KubernetesClient')
    def test_main_exception_still_flushes_telemetry(
        self,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord,
    ):
        """Test that exceptions don't prevent telemetry flush."""
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        mock_meter_provider = Mock()
        mock_setup_telemetry.return_value = (mock_meter_provider, None)
        mock_create_metrics.return_value = None

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.side_effect = RuntimeError("Test error")
        mock_scanner.return_value = mock_scanner_instance

        with pytest.raises(RuntimeError):
            main()

        mock_meter_provider.force_flush.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()

    @patch('scan.main.DiscordNotifier')
    @patch('scan.main.logging')
    @patch('scan.main.Config')
    @patch('scan.main.setup_telemetry')
    @patch('scan.main.create_metrics')
    @patch('scan.main.TrivyScanner')
    @patch('scan.main.KubernetesClient')
    @patch('scan.main.send_scan_metrics')
    def test_main_logs_warning_when_db_update_fails_and_emits_metrics(
        self,
        mock_send_metrics,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        _mock_logging,
        _mock_discord,
    ):
        """Covers: db_update=False branch and the scanner_metrics branch."""
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        mock_setup_telemetry.return_value = (None, None)
        mock_metrics = Mock()
        mock_create_metrics.return_value = mock_metrics

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = False  # exercise the warning branch
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        main()

        mock_send_metrics.assert_called_once()


class TestSendScanMetrics:
    """Tests for send_scan_metrics helper."""

    def test_sets_critical_and_high_gauges_per_scan_result(self):
        """send_scan_metrics emits one critical + one high gauge call per scan result."""
        from scan.scanner import CompleteScanResult, ScanResult
        from oke_scanner_core.image import Image

        complete = CompleteScanResult()
        scan = ScanResult(Image("test.ocir.io/ns/app:v1.0.0"))
        scan.critical_count = 2
        scan.high_count = 3
        complete.add_result(scan, scan.image)

        metrics = Mock()
        send_scan_metrics(metrics, complete)

        assert metrics.scan_total.set.call_count == 2
        call_args = [call.args for call in metrics.scan_total.set.call_args_list]
        assert (2, {'image': 'ns/app', 'severity': 'critical'}) in call_args
        assert (3, {'image': 'ns/app', 'severity': 'high'}) in call_args
