"""Tests for main module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.main import main, setup_otel


class TestSetupOtel:
    """Tests for setup_otel function."""

    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    def test_setup_otel_with_all_providers(self, mock_create_metrics, mock_setup_telemetry, base_config):
        """Test setup_otel with all providers enabled."""
        mock_trace_provider = Mock()
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (mock_trace_provider, mock_meter_provider, mock_logger_provider)

        mock_metrics = Mock()
        mock_create_metrics.return_value = mock_metrics

        trace_provider, logger_provider, metrics = setup_otel(base_config)

        assert trace_provider == mock_trace_provider
        assert logger_provider == mock_logger_provider
        assert metrics == mock_metrics

    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    def test_setup_otel_with_no_providers(self, mock_create_metrics, mock_setup_telemetry, base_config):
        """Test setup_otel when all providers are disabled."""
        mock_setup_telemetry.return_value = (None, None, None)
        mock_create_metrics.return_value = None

        trace_provider, logger_provider, metrics = setup_otel(base_config)

        assert trace_provider is None
        assert logger_provider is None
        assert metrics is None


class TestMain:
    """Tests for main function."""

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_successful_run(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord
    ):
        """Test main successful run."""
        # Setup config
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config.ocir_cleanup_enabled = False
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry
        mock_trace_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (mock_trace_provider, None, mock_logger_provider)
        mock_create_metrics.return_value = None

        # Setup scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        # Setup k8s client
        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        # Setup registry client
        mock_registry_instance = Mock()
        mock_registry_instance.check_image_updates.return_value = None
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        main()

        # Should not call sys.exit on success
        mock_sys.exit.assert_not_called()

        # Should flush telemetry
        mock_trace_provider.force_flush.assert_called_once()
        mock_logger_provider.force_flush.assert_called_once()

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_with_discord_notification(
        self,
        mock_sys,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord
    ):
        """Test main sends Discord notification when URL is configured."""
        # Setup config with discord URL
        mock_config = Mock()
        mock_config.discord_webhook_url = "https://discord.com/webhook"
        mock_config.ocir_cleanup_enabled = False
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry (disabled)
        mock_setup_telemetry.return_value = (None, None, None)
        mock_create_metrics.return_value = None

        # Setup scanner
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        # Setup k8s client with one image
        mock_k8s_instance = Mock()
        from src.k8s_client import Image
        mock_k8s_instance.get_all_images.return_value = {Image("test.ocir.io/ns/app:v1")}
        mock_k8s_client.return_value = mock_k8s_instance

        # Setup registry client
        mock_registry_instance = Mock()
        mock_registry_instance.check_image_updates.return_value = None
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        main()

        # Discord notifier should be called
        mock_discord.assert_called()

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    def test_main_exception_still_flushes_telemetry(
        self,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        mock_logging,
        mock_discord
    ):
        """Test that exceptions don't prevent telemetry flush."""
        # Setup config
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry
        mock_trace_provider = Mock()
        mock_setup_telemetry.return_value = (mock_trace_provider, None, None)
        mock_create_metrics.return_value = None

        # Setup scanner to raise exception
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.side_effect = RuntimeError("Test error")
        mock_scanner.return_value = mock_scanner_instance

        # Should raise the exception
        with pytest.raises(RuntimeError):
            main()

        # Telemetry should still be flushed in finally block
        mock_trace_provider.force_flush.assert_called_once()
        mock_trace_provider.shutdown.assert_called_once()
