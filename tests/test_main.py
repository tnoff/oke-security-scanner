"""Tests for main module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.main import main


class TestMain:
    """Tests for main function."""

    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_providers_initialized_as_none(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging
    ):
        """Test that providers are initialized as None before try block."""
        # Setup mocks
        mock_config = Mock()
        mock_config_class.from_env.return_value = mock_config

        # Simulate error before setup_telemetry is called
        mock_config.validate.side_effect = ValueError("Config error")

        # Run main - should catch exception and call sys.exit(1)
        main()

        # Verify sys.exit was called with 1 due to ValueError
        mock_sys.exit.assert_called_once_with(1)
        # The test passes if no AttributeError is raised about undefined variables

    @patch('src.main.VersionReporter')
    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_with_all_providers_enabled(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord,
        mock_reporter
    ):
        """Test main with all OTLP providers enabled."""
        # Setup config
        mock_config = Mock()
        mock_config.otlp_traces_enabled = True
        mock_config.otlp_metrics_enabled = True
        mock_config.otlp_logs_enabled = True
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry providers
        mock_trace_provider = Mock()
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (
            mock_trace_provider,
            mock_meter_provider,
            mock_logger_provider
        )

        # Setup metrics
        mock_metrics = {'scan_total': Mock()}
        mock_create_metrics.return_value = mock_metrics

        # Setup scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = {'CRITICAL': 0, 'HIGH': 0}
        mock_scanner.return_value = mock_scanner_instance

        # Setup k8s client
        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        # Run main
        main()

        # Verify providers were flushed and shutdown
        mock_trace_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_trace_provider.shutdown.assert_called_once()
        mock_meter_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_meter_provider.shutdown.assert_called_once()
        mock_logger_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_logger_provider.shutdown.assert_called_once()
        # Successful completion doesn't call sys.exit
        mock_sys.exit.assert_not_called()

    @patch('src.main.VersionReporter')
    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_with_all_providers_disabled(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord,
        mock_reporter
    ):
        """Test main with all OTLP providers disabled (None)."""
        # Setup config
        mock_config = Mock()
        mock_config.otlp_traces_enabled = False
        mock_config.otlp_metrics_enabled = False
        mock_config.otlp_logs_enabled = False
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry providers - all None
        mock_setup_telemetry.return_value = (None, None, None)

        # Setup metrics - None when meter_provider is None
        mock_create_metrics.return_value = None

        # Setup scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = {'CRITICAL': 0, 'HIGH': 0}
        mock_scanner.return_value = mock_scanner_instance

        # Setup k8s client
        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        # Run main - should not raise AttributeError
        main()

        # Verify no force_flush calls since providers are None
        # (no way to assert "not called" on None, so just verify no exceptions)
        # Successful completion doesn't call sys.exit
        mock_sys.exit.assert_not_called()

    @patch('src.main.VersionReporter')
    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_with_mixed_providers(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord,
        mock_reporter
    ):
        """Test main with some providers enabled and some disabled."""
        # Setup config
        mock_config = Mock()
        mock_config.otlp_traces_enabled = True
        mock_config.otlp_metrics_enabled = False
        mock_config.otlp_logs_enabled = True
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry providers - mixed
        mock_trace_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (
            mock_trace_provider,
            None,  # meter_provider disabled
            mock_logger_provider
        )

        # Setup metrics - None when meter_provider is None
        mock_create_metrics.return_value = None

        # Setup scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = {'CRITICAL': 0, 'HIGH': 0}
        mock_scanner.return_value = mock_scanner_instance

        # Setup k8s client
        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        # Run main
        main()

        # Verify only enabled providers were flushed
        mock_trace_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_trace_provider.shutdown.assert_called_once()
        mock_logger_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_logger_provider.shutdown.assert_called_once()
        # Successful completion doesn't call sys.exit
        mock_sys.exit.assert_not_called()

    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_exception_during_scan(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging
    ):
        """Test main handles exceptions and still shuts down providers properly."""
        # Setup config
        mock_config = Mock()
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry providers
        mock_trace_provider = Mock()
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (
            mock_trace_provider,
            mock_meter_provider,
            mock_logger_provider
        )

        # Setup metrics
        mock_metrics = {'scan_total': Mock()}
        mock_create_metrics.return_value = mock_metrics

        # Setup scanner to raise exception
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.side_effect = Exception("Scan error")
        mock_scanner.return_value = mock_scanner_instance

        # Run main - should catch exception and call sys.exit(1)
        main()

        # Verify sys.exit was called with 1 due to exception
        mock_sys.exit.assert_called_once_with(1)

        # Verify providers were still shut down properly in finally block
        mock_trace_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_trace_provider.shutdown.assert_called_once()
        mock_meter_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_meter_provider.shutdown.assert_called_once()
        mock_logger_provider.force_flush.assert_called_once_with(timeout_millis=30000)
        mock_logger_provider.shutdown.assert_called_once()
