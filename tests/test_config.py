"""Tests for config module."""

import os
import pytest
from src.config import Config


class TestConfig:
    """Tests for Config class."""

    def test_from_env_with_all_values(self, monkeypatch):
        """Test Config.from_env with all environment variables set."""
        # Set all required environment variables
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")
        monkeypatch.setenv("OTLP_ENDPOINT", "http://localhost:4318")
        monkeypatch.setenv("OTLP_INSECURE", "true")
        monkeypatch.setenv("OTLP_TRACES_ENABLED", "true")
        monkeypatch.setenv("OTLP_METRICS_ENABLED", "true")
        monkeypatch.setenv("OTLP_LOGS_ENABLED", "true")
        monkeypatch.setenv("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM")
        monkeypatch.setenv("TRIVY_TIMEOUT", "600")
        monkeypatch.setenv("SCAN_NAMESPACES", "default,kube-system")
        monkeypatch.setenv("EXCLUDE_NAMESPACES", "kube-node-lease")
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/test")

        config = Config.from_env()

        assert config.oci_registry == "test.ocir.io"
        assert config.oci_username == "testuser"
        assert config.oci_token == "testtoken"
        assert config.oci_namespace == "testnamespace"
        assert config.otlp_endpoint == "http://localhost:4318"
        assert config.otlp_insecure is True
        assert config.otlp_traces_enabled is True
        assert config.otlp_metrics_enabled is True
        assert config.otlp_logs_enabled is True
        assert config.trivy_severity == "CRITICAL,HIGH,MEDIUM"
        assert config.trivy_timeout == 600
        assert config.namespaces == ["default", "kube-system"]
        assert config.exclude_namespaces == ["kube-node-lease"]
        assert config.discord_webhook_url == "https://discord.com/api/webhooks/test"

    def test_from_env_with_defaults(self, monkeypatch):
        """Test Config.from_env with default values."""
        # Only set required values
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")

        config = Config.from_env()

        # Check defaults
        assert config.otlp_endpoint == "http://localhost:4317"
        assert config.otlp_insecure is True
        assert config.otlp_traces_enabled is True
        assert config.otlp_metrics_enabled is True
        assert config.otlp_logs_enabled is True
        assert config.trivy_severity == "CRITICAL,HIGH"
        assert config.trivy_timeout == 300
        assert config.namespaces == []
        assert config.exclude_namespaces == ["kube-system", "kube-public", "kube-node-lease"]
        assert config.discord_webhook_url == ""

    def test_from_env_otlp_insecure_false(self, monkeypatch):
        """Test OTLP_INSECURE=false."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")
        monkeypatch.setenv("OTLP_INSECURE", "false")

        config = Config.from_env()
        assert config.otlp_insecure is False

    def test_validate_success(self, monkeypatch):
        """Test validate() with all required fields present."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")

        config = Config.from_env()
        config.validate()  # Should not raise

    def test_validate_missing_registry(self, monkeypatch):
        """Test validate() with missing OCI_REGISTRY."""
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")

        config = Config.from_env()
        with pytest.raises(ValueError, match="Missing required environment variables: OCI_REGISTRY"):
            config.validate()

    def test_validate_missing_multiple(self, monkeypatch):
        """Test validate() with multiple missing fields."""
        config = Config.from_env()
        with pytest.raises(ValueError, match="Missing required environment variables"):
            config.validate()

    def test_discord_webhook_url_empty_by_default(self, monkeypatch):
        """Test that Discord webhook URL is empty by default."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")

        config = Config.from_env()
        assert config.discord_webhook_url == ""

    def test_otlp_traces_disabled(self, monkeypatch):
        """Test OTLP_TRACES_ENABLED=false."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")
        monkeypatch.setenv("OTLP_TRACES_ENABLED", "false")

        config = Config.from_env()
        assert config.otlp_traces_enabled is False
        assert config.otlp_metrics_enabled is True  # Others still default to true
        assert config.otlp_logs_enabled is True

    def test_otlp_metrics_disabled(self, monkeypatch):
        """Test OTLP_METRICS_ENABLED=false."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")
        monkeypatch.setenv("OTLP_METRICS_ENABLED", "false")

        config = Config.from_env()
        assert config.otlp_traces_enabled is True
        assert config.otlp_metrics_enabled is False
        assert config.otlp_logs_enabled is True

    def test_otlp_logs_disabled(self, monkeypatch):
        """Test OTLP_LOGS_ENABLED=false."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")
        monkeypatch.setenv("OTLP_LOGS_ENABLED", "false")

        config = Config.from_env()
        assert config.otlp_traces_enabled is True
        assert config.otlp_metrics_enabled is True
        assert config.otlp_logs_enabled is False

    def test_all_otlp_disabled(self, monkeypatch):
        """Test all OTLP components disabled."""
        monkeypatch.setenv("OCI_REGISTRY", "test.ocir.io")
        monkeypatch.setenv("OCI_USERNAME", "testuser")
        monkeypatch.setenv("OCI_TOKEN", "testtoken")
        monkeypatch.setenv("OCI_NAMESPACE", "testnamespace")
        monkeypatch.setenv("OTLP_TRACES_ENABLED", "false")
        monkeypatch.setenv("OTLP_METRICS_ENABLED", "false")
        monkeypatch.setenv("OTLP_LOGS_ENABLED", "false")

        config = Config.from_env()
        assert config.otlp_traces_enabled is False
        assert config.otlp_metrics_enabled is False
        assert config.otlp_logs_enabled is False
