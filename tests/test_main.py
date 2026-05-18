"""Tests for main module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.main import main, setup_otel, send_scan_metrics, run_cleanup


class TestSetupOtel:
    """Tests for setup_otel function."""

    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
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

    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
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
        mock_config.enable_scan = True
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry
        mock_meter_provider = Mock()
        mock_logger_provider = Mock()
        mock_setup_telemetry.return_value = (mock_meter_provider, mock_logger_provider)
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
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        main()

        # Should not call sys.exit on success
        mock_sys.exit.assert_not_called()

        # Should flush telemetry
        mock_meter_provider.force_flush.assert_called_once()
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
        mock_config.enable_scan = True
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry (disabled)
        mock_setup_telemetry.return_value = (None, None)
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
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
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
    @patch('src.main.sys')
    def test_main_cleanup_enabled_skips_recommendations_sends_deletion(
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
        """When cleanup is enabled, send_cleanup_recommendations is skipped and send_deletion_results is sent."""
        mock_config = Mock()
        mock_config.discord_webhook_url = "https://discord.com/webhook"
        mock_config.ocir_cleanup_enabled = True
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config.enable_scan = True
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = ""
        mock_config_class.from_env.return_value = mock_config

        mock_setup_telemetry.return_value = (None, None)
        mock_create_metrics.return_value = None

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.delete_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        mock_notifier = Mock()
        mock_discord.return_value = mock_notifier

        main()

        mock_notifier.send_cleanup_recommendations.assert_not_called()
        mock_notifier.send_deletion_results.assert_called()

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_cleanup_disabled_sends_recommendations_skips_deletion(
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
        """When cleanup is disabled, send_cleanup_recommendations is sent and send_deletion_results is skipped."""
        mock_config = Mock()
        mock_config.discord_webhook_url = "https://discord.com/webhook"
        mock_config.ocir_cleanup_enabled = False
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config.enable_scan = True
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = ""
        mock_config_class.from_env.return_value = mock_config

        mock_setup_telemetry.return_value = (None, None)
        mock_create_metrics.return_value = None

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        mock_notifier = Mock()
        mock_discord.return_value = mock_notifier

        main()

        mock_notifier.send_cleanup_recommendations.assert_called()
        mock_notifier.send_deletion_results.assert_not_called()

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
        mock_config.enable_scan = True
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = ""
        mock_config_class.from_env.return_value = mock_config

        # Setup telemetry
        mock_meter_provider = Mock()
        mock_setup_telemetry.return_value = (mock_meter_provider, None)
        mock_create_metrics.return_value = None

        # Setup scanner to raise exception
        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.side_effect = RuntimeError("Test error")
        mock_scanner.return_value = mock_scanner_instance

        # Should raise the exception
        with pytest.raises(RuntimeError):
            main()

        # Telemetry should still be flushed in finally block
        mock_meter_provider.force_flush.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()

    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.sys')
    def test_main_exits_on_config_value_error(self, mock_sys, mock_config_class, _mock_logging):
        """A ValueError from Config.from_env triggers sys.exit(1)."""
        mock_sys.exit.side_effect = SystemExit
        mock_config_class.from_env.side_effect = ValueError("bad config")

        with pytest.raises(SystemExit):
            main()

        mock_sys.exit.assert_called_once_with(1)

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.send_scan_metrics')
    @patch('src.main.sys')
    def test_main_logs_warning_when_db_update_fails_and_emits_metrics_and_orphan_logs(
        self,
        mock_sys,
        mock_send_metrics,
        mock_registry_client,
        mock_k8s_client,
        mock_scanner,
        mock_create_metrics,
        mock_setup_telemetry,
        mock_config_class,
        _mock_logging,
        _mock_discord,
    ):
        """Covers: db_update=False branch, scanner_metrics branch, orphan-recs log loop, orphans-deleted log."""
        from src.k8s_client import Image
        from src.registry_client import CleanupRecommendation

        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config.ocir_cleanup_enabled = True
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config.enable_scan = True
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = ""
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

        # Orphan recs returns a recommendation so the per-rec log line runs;
        # delete returns a non-empty list so the "Deleted N" log line runs too.
        deleted_image = Image("test.ocir.io/ns/app:unknown", digest="sha256:abc")
        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = [
            CleanupRecommendation("test.ocir.io", "ns/app", [deleted_image]),
        ]
        mock_registry_instance.delete_ocir_images.return_value = [deleted_image]
        mock_registry_client.return_value = mock_registry_instance

        main()

        # scanner_metrics path was exercised
        mock_send_metrics.assert_called_once()
        # delete_ocir_images called twice (cleanup recs path + orphan recs path)
        assert mock_registry_instance.delete_ocir_images.call_count == 2


class TestPhaseToggles:
    """Tests for the ENABLE_SCAN / ENABLE_CLEANUP / CLEANUP_REPO phase toggles."""

    @staticmethod
    def _make_config(**overrides):
        from src.config import Config
        defaults = dict(
            otlp_endpoint="http://localhost:4318", otlp_insecure=True,
            otlp_metrics_enabled=False, otlp_logs_enabled=False,
            trivy_severity="CRITICAL,HIGH", trivy_timeout=300, trivy_platform="",
            namespaces=[], exclude_namespaces=[],
            discord_webhook_url="",
            ocir_cleanup_enabled=True, ocir_cleanup_keep_count=5,
            ocir_extra_repositories=[],
            enable_scan=True, enable_cleanup=True, cleanup_repo="",
        )
        defaults.update(overrides)
        return Config(**defaults)

    @patch('src.main.DiscordNotifier')
    @patch('src.main.RegistryClient')
    @patch('src.main.KubernetesClient')
    def test_run_cleanup_scoped_to_cleanup_repo(
        self, mock_k8s_client, mock_registry_client, _mock_discord
    ):
        """CLEANUP_REPO set: only images for that repo are forwarded, and the repo
        is always included via extra_repositories so cleanup runs even when nothing
        is deployed."""
        from src.k8s_client import Image

        cfg = self._make_config(
            discord_webhook_url="https://discord.com/wh",
            ocir_extra_repositories=["unused/other"],  # must be overridden by cleanup_repo
            enable_scan=False,
            cleanup_repo="tnoff/discord_bot",
        )

        target = Image("iad.ocir.io/tnoff/discord_bot:abc123")
        other = Image("iad.ocir.io/tnoff/other_app:def456")
        non_ocir = Image("docker.io/library/postgres:16")
        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = {target, other, non_ocir}
        mock_k8s_client.return_value = mock_k8s_instance

        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.delete_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        run_cleanup(cfg, None, None)

        # Scoped image set + cleanup_repo as the only extra
        call = mock_registry_instance.get_old_ocir_images.call_args
        assert call.args[0] == {target}
        assert call.kwargs["extra_repositories"] == ["tnoff/discord_bot"]
        assert call.kwargs["keep_count"] == 5

        orphan_call = mock_registry_instance.get_orphaned_manifests.call_args
        assert orphan_call.args[0] == {target}
        assert orphan_call.kwargs["extra_repositories"] == ["tnoff/discord_bot"]

    @patch('src.main.DiscordNotifier')
    @patch('src.main.RegistryClient')
    @patch('src.main.KubernetesClient')
    def test_run_cleanup_works_with_nothing_deployed(
        self, mock_k8s_client, mock_registry_client, _mock_discord
    ):
        """First push of a brand-new repo: nothing deployed, cleanup still runs via
        the extra_repositories codepath."""
        cfg = self._make_config(
            ocir_cleanup_enabled=False,  # dry-run
            enable_scan=False,
            cleanup_repo="tnoff/new_repo",
        )

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        run_cleanup(cfg, None, None)

        mock_registry_instance.get_old_ocir_images.assert_called_once()
        mock_registry_instance.get_orphaned_manifests.assert_called_once()
        mock_registry_instance.delete_ocir_images.assert_not_called()

    @patch('src.main.DiscordNotifier')
    @patch('src.main.RegistryClient')
    @patch('src.main.KubernetesClient')
    def test_run_cleanup_unscoped_reuses_discovered_images(
        self, mock_k8s_client, mock_registry_client, _mock_discord
    ):
        """When discovered_images is supplied (i.e. scan already ran), cleanup
        does NOT re-list pods — important so the daily cron only queries k8s once."""
        from src.k8s_client import Image

        cfg = self._make_config(ocir_extra_repositories=["tnoff/extra_repo"])

        prediscovered = {Image("iad.ocir.io/tnoff/a:v1")}
        mock_k8s_instance = Mock()
        mock_k8s_client.return_value = mock_k8s_instance

        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.delete_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        run_cleanup(cfg, None, None, discovered_images=prediscovered)

        mock_k8s_client.assert_not_called()
        call = mock_registry_instance.get_old_ocir_images.call_args
        assert call.args[0] == prediscovered
        # Unscoped run uses config.ocir_extra_repositories
        assert call.kwargs["extra_repositories"] == ["tnoff/extra_repo"]

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_with_scan_disabled_skips_trivy(
        self, _mock_sys, mock_registry_client, mock_k8s_client, mock_scanner,
        _mock_create_metrics, mock_setup_telemetry, mock_config_class,
        _mock_logging, _mock_discord,
    ):
        """ENABLE_SCAN=false: TrivyScanner is never constructed but cleanup still runs."""
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config.ocir_cleanup_enabled = False
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config.enable_scan = False
        mock_config.enable_cleanup = True
        mock_config.cleanup_repo = "tnoff/discord_bot"
        mock_config_class.from_env.return_value = mock_config

        mock_setup_telemetry.return_value = (None, None)

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        mock_registry_instance = Mock()
        mock_registry_instance.get_old_ocir_images.return_value = []
        mock_registry_instance.get_orphaned_manifests.return_value = []
        mock_registry_client.return_value = mock_registry_instance

        main()

        mock_scanner.assert_not_called()
        mock_registry_instance.get_old_ocir_images.assert_called_once()

    @patch('src.main.DiscordNotifier')
    @patch('src.main.logging')
    @patch('src.main.Config')
    @patch('src.main.setup_telemetry')
    @patch('src.main.create_metrics')
    @patch('src.main.TrivyScanner')
    @patch('src.main.KubernetesClient')
    @patch('src.main.RegistryClient')
    @patch('src.main.sys')
    def test_main_with_cleanup_disabled_skips_registry(
        self, _mock_sys, mock_registry_client, mock_k8s_client, mock_scanner,
        _mock_create_metrics, mock_setup_telemetry, mock_config_class,
        _mock_logging, _mock_discord,
    ):
        """ENABLE_CLEANUP=false: RegistryClient is never constructed but scan still runs."""
        mock_config = Mock()
        mock_config.discord_webhook_url = ""
        mock_config.ocir_cleanup_enabled = False
        mock_config.ocir_cleanup_keep_count = 5
        mock_config.ocir_extra_repositories = []
        mock_config.enable_scan = True
        mock_config.enable_cleanup = False
        mock_config.cleanup_repo = ""
        mock_config_class.from_env.return_value = mock_config

        mock_setup_telemetry.return_value = (None, None)

        mock_scanner_instance = Mock()
        mock_scanner_instance.update_database.return_value = True
        mock_scanner_instance.scan_image.return_value = None
        mock_scanner.return_value = mock_scanner_instance

        mock_k8s_instance = Mock()
        mock_k8s_instance.get_all_images.return_value = set()
        mock_k8s_client.return_value = mock_k8s_instance

        main()

        mock_scanner.assert_called_once()
        mock_registry_client.assert_not_called()


class TestSendScanMetrics:
    """Tests for send_scan_metrics helper."""

    def test_sets_critical_and_high_gauges_per_scan_result(self):
        """send_scan_metrics emits one critical + one high gauge call per scan result."""
        from src.scanner import CompleteScanResult, ScanResult
        from src.k8s_client import Image

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
