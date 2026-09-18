"""Test SecretAgeConfig env-var loading."""

import os

from src.secret_age.config import SecretAgeConfig


def test_defaults_when_env_empty(monkeypatch):
    for k in list(os.environ):
        if k.startswith(("SECRET_AGE_", "LAYER1_", "OCI_TENANCY_", "ENABLE_", "DISCORD_")):
            monkeypatch.delenv(k, raising=False)
    cfg = SecretAgeConfig.from_env()
    assert cfg.warn_days == 90
    assert cfg.rotate_days == 180
    assert cfg.layer1_configmap_name == "layer-1-rotation-ledger"
    assert cfg.enable_oci_reader is True


def test_thresholds_override(monkeypatch):
    monkeypatch.setenv("SECRET_AGE_WARN_DAYS", "30")
    monkeypatch.setenv("SECRET_AGE_ROTATE_DAYS", "60")
    cfg = SecretAgeConfig.from_env()
    assert cfg.warn_days == 30
    assert cfg.rotate_days == 60


def test_reader_toggle_off(monkeypatch):
    monkeypatch.setenv("ENABLE_OCI_READER", "false")
    cfg = SecretAgeConfig.from_env()
    assert cfg.enable_oci_reader is False
    assert cfg.enable_k8s_reader is True
