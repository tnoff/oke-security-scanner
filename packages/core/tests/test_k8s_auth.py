"""Tests for the shared k8s auth bootstrap."""

from unittest.mock import patch

from oke_scanner_core.k8s_auth import load_k8s_config


@patch('oke_scanner_core.k8s_auth.k8s_config.load_incluster_config')
def test_load_k8s_config_loads_incluster_config(mock_load_config):
    """In-cluster config loads without falling back."""
    load_k8s_config()
    mock_load_config.assert_called_once()


@patch('oke_scanner_core.k8s_auth.k8s_config.load_kube_config')
@patch('oke_scanner_core.k8s_auth.k8s_config.load_incluster_config')
def test_load_k8s_config_falls_back_to_kubeconfig(mock_incluster, mock_kubeconfig):
    """ConfigException from in-cluster config triggers load_kube_config fallback."""
    from kubernetes.config import ConfigException
    mock_incluster.side_effect = ConfigException("not running in cluster")

    load_k8s_config()

    mock_incluster.assert_called_once()
    mock_kubeconfig.assert_called_once()
