"""Tests for config module."""

import pytest
from src.config import Config


class TestConfig:
    """Tests for Config class."""

    def test_from_env_with_all_values(self, monkeypatch):
        """Test Config.from_env with all environment variables set."""
        monkeypatch.setenv("OTLP_ENDPOINT", "http://localhost:4318")
        monkeypatch.setenv("OTLP_INSECURE", "true")
        monkeypatch.setenv("OTLP_TRACES_ENABLED", "true")
        monkeypatch.setenv("OTLP_METRICS_ENABLED", "true")
        monkeypatch.setenv("OTLP_LOGS_ENABLED", "true")
        monkeypatch.setenv("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM")
        monkeypatch.setenv("TRIVY_TIMEOUT", "600")
        monkeypatch.setenv("TRIVY_PLATFORM", "linux/arm64")
        monkeypatch.setenv("SCAN_NAMESPACES", "default,kube-system")
        monkeypatch.setenv("EXCLUDE_NAMESPACES", "kube-node-lease")
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")
        monkeypatch.setenv("OCIR_CLEANUP_ENABLED", "true")
        monkeypatch.setenv("OCIR_CLEANUP_KEEP_COUNT", "10")
        monkeypatch.setenv("OCIR_EXTRA_REPOSITORIES", "repo1,repo2")
        monkeypatch.setenv("OKE_IMAGE_CHECK_ENABLED", "true")
        monkeypatch.setenv("OKE_CLUSTER_OCID", "ocid1.cluster.oc1.test")

        config = Config.from_env()

        assert config.otlp_endpoint == "http://localhost:4318"
        assert config.otlp_insecure is True
        assert config.otlp_traces_enabled is True
        assert config.otlp_metrics_enabled is True
        assert config.otlp_logs_enabled is True
        assert config.trivy_severity == "CRITICAL,HIGH,MEDIUM"
        assert config.trivy_timeout == 600
        assert config.trivy_platform == "linux/arm64"
        assert config.namespaces == ["default", "kube-system"]
        assert config.exclude_namespaces == ["kube-node-lease"]
        assert config.discord_webhook_url == "https://discord.com/api/webhooks/test"
        assert config.ocir_cleanup_enabled is True
        assert config.ocir_cleanup_keep_count == 10
        assert config.ocir_extra_repositories == ["repo1", "repo2"]
        assert config.oke_image_check_enabled is True
        assert config.oke_cluster_ocid == "ocid1.cluster.oc1.test"

    def test_from_env_with_defaults(self):
        """Test Config.from_env with default values."""
        config = Config.from_env()

        # Check defaults
        assert config.otlp_endpoint == "http://localhost:4317"
        assert config.otlp_insecure is True
        assert config.otlp_traces_enabled is False
        assert config.otlp_metrics_enabled is False
        assert config.otlp_logs_enabled is False
        assert config.trivy_severity == "CRITICAL,HIGH"
        assert config.trivy_timeout == 300
        assert config.trivy_platform == ""
        assert config.namespaces == []
        assert config.exclude_namespaces == ["kube-system", "kube-public", "kube-node-lease"]
        assert config.discord_webhook_url == ""
        assert config.ocir_cleanup_enabled is False
        assert config.ocir_cleanup_keep_count == 5
        assert config.oke_image_check_enabled is False
        assert config.oke_cluster_ocid == ""

    def test_from_env_otlp_insecure_false(self, monkeypatch):
        """Test OTLP_INSECURE=false."""
        monkeypatch.setenv("OTLP_INSECURE", "false")

        config = Config.from_env()
        assert config.otlp_insecure is False

    def test_discord_webhook_url_empty_by_default(self):
        """Test that Discord webhook URL is empty by default."""
        config = Config.from_env()
        assert config.discord_webhook_url == ""

    def test_otlp_traces_enabled(self, monkeypatch):
        """Test OTLP_TRACES_ENABLED=true."""
        monkeypatch.setenv("OTLP_TRACES_ENABLED", "true")

        config = Config.from_env()
        assert config.otlp_traces_enabled is True

    def test_otlp_metrics_enabled(self, monkeypatch):
        """Test OTLP_METRICS_ENABLED=true."""
        monkeypatch.setenv("OTLP_METRICS_ENABLED", "true")

        config = Config.from_env()
        assert config.otlp_metrics_enabled is True

    def test_otlp_logs_enabled(self, monkeypatch):
        """Test OTLP_LOGS_ENABLED=true."""
        monkeypatch.setenv("OTLP_LOGS_ENABLED", "true")

        config = Config.from_env()
        assert config.otlp_logs_enabled is True

    def test_ocir_cleanup_enabled(self, monkeypatch):
        """Test OCIR_CLEANUP_ENABLED=true."""
        monkeypatch.setenv("OCIR_CLEANUP_ENABLED", "true")

        config = Config.from_env()
        assert config.ocir_cleanup_enabled is True

    def test_ocir_cleanup_keep_count(self, monkeypatch):
        """Test OCIR_CLEANUP_KEEP_COUNT setting."""
        monkeypatch.setenv("OCIR_CLEANUP_KEEP_COUNT", "10")

        config = Config.from_env()
        assert config.ocir_cleanup_keep_count == 10

    def test_oke_image_check_enabled(self, monkeypatch):
        """Test OKE_IMAGE_CHECK_ENABLED=true."""
        monkeypatch.setenv("OKE_IMAGE_CHECK_ENABLED", "true")

        config = Config.from_env()
        assert config.oke_image_check_enabled is True

    def test_oke_image_check_disabled_by_default(self):
        """Test OKE_IMAGE_CHECK_ENABLED defaults to false."""
        config = Config.from_env()
        assert config.oke_image_check_enabled is False

    def test_oke_cluster_ocid(self, monkeypatch):
        """Test OKE_CLUSTER_OCID setting."""
        monkeypatch.setenv("OKE_CLUSTER_OCID", "ocid1.cluster.oc1.test")

        config = Config.from_env()
        assert config.oke_cluster_ocid == "ocid1.cluster.oc1.test"

    def test_oke_cluster_ocid_empty_by_default(self):
        """Test OKE_CLUSTER_OCID defaults to empty string."""
        config = Config.from_env()
        assert config.oke_cluster_ocid == ""

    def test_trivy_platform(self, monkeypatch):
        """Test TRIVY_PLATFORM setting."""
        monkeypatch.setenv("TRIVY_PLATFORM", "linux/arm64")

        config = Config.from_env()
        assert config.trivy_platform == "linux/arm64"

    def test_trivy_platform_empty_by_default(self):
        """Test TRIVY_PLATFORM defaults to empty string."""
        config = Config.from_env()
        assert config.trivy_platform == ""
