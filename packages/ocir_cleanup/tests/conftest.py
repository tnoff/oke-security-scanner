"""Shared test fixtures for cleanup tests."""

import pytest
from unittest.mock import Mock
from ocir_cleanup.config import CleanupConfig


@pytest.fixture
def base_config():
    """Create a base test configuration with all required fields."""
    return CleanupConfig(
        otlp_endpoint="http://localhost:4318",
        otlp_insecure=True,
        otlp_metrics_enabled=True,
        otlp_logs_enabled=True,
        namespaces=[],
        exclude_namespaces=["kube-system", "kube-public"],
        discord_webhook_url="",
        ocir_cleanup_enabled=False,
        ocir_cleanup_keep_count=5,
        ocir_extra_repositories=[],
        cleanup_protect_tags_regex="",
        cleanup_group_by_regex="",
        cleanup_repo="",
    )


@pytest.fixture
def mock_logger_provider():
    """Create a mock logger provider."""
    return Mock()
