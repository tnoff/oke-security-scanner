"""Shared fixtures for secret_age tests."""

import pytest

from src.secret_age.config import SecretAgeConfig


@pytest.fixture
def cfg():
    """Default tracker config — readers all enabled, default thresholds."""
    return SecretAgeConfig(
        discord_webhook_url="",
        warn_days=90,
        rotate_days=180,
        gitlab_url="https://gitlab.com",
        gitlab_token="test-token",
        docker_apps_project="tnoff-projects/docker-apps",
        sealed_secret_paths=["apps/discord/secrets-conf.yaml"],
        layer1_configmap_name="layer-1-rotation-ledger",
        layer1_configmap_namespace="security-scanner",
        oci_tenancy_ocid="ocid1.tenancy.oc1..test",
    )
