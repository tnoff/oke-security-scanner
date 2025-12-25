"""Tests for k8s_client module."""

import pytest
from unittest.mock import Mock, patch
from src.k8s_client import KubernetesClient
from src.config import Config


class TestKubernetesClient:
    """Tests for KubernetesClient class."""

    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        return Config(
            oci_registry="test.ocir.io",
            oci_username="testuser",
            oci_token="testtoken",
            oci_namespace="testnamespace",
            otlp_endpoint="http://localhost:4318",
            otlp_insecure=True,
            trivy_severity="CRITICAL,HIGH",
            trivy_timeout=300,
            namespaces=["default", "production"],
            exclude_namespaces=["kube-system", "kube-public"],
            discord_webhook_url="",
        )

    @pytest.fixture
    def logger_provider(self):
        """Create mock logger provider."""
        return Mock()

    @pytest.fixture
    def k8s_client(self, config, logger_provider):
        """Create a KubernetesClient instance."""
        with patch('src.k8s_client.config.load_incluster_config'), \
             patch('src.k8s_client.client.CoreV1Api'), \
             patch('src.k8s_client.client.AppsV1Api'), \
             patch('src.k8s_client.tracer'):
            return KubernetesClient(config, logger_provider)

    @patch('src.k8s_client.tracer')
    @patch('src.k8s_client.client.AppsV1Api')
    @patch('src.k8s_client.client.CoreV1Api')
    @patch('src.k8s_client.config.load_incluster_config')
    def test_init_loads_incluster_config(self, mock_load_config, mock_core_api, mock_apps_api, mock_tracer, config, logger_provider):
        """Test that initialization loads in-cluster config."""
        KubernetesClient(config, logger_provider)
        mock_load_config.assert_called_once()

    def test_get_namespaces_uses_configured_namespaces(self, k8s_client):
        """Test _get_namespaces returns configured namespaces."""
        with patch('src.k8s_client.tracer'):
            namespaces = k8s_client._get_namespaces()
            assert namespaces == ["default", "production"]

    def test_get_namespaces_without_config_discovers_all(self, logger_provider):
        """Test _get_namespaces discovers namespaces when none configured."""
        config = Config(
            oci_registry="test.ocir.io",
            oci_username="testuser",
            oci_token="testtoken",
            oci_namespace="testnamespace",
            otlp_endpoint="http://localhost:4318",
            otlp_insecure=True,
            trivy_severity="CRITICAL,HIGH",
            trivy_timeout=300,
            namespaces=[],  # Empty - discover all
            exclude_namespaces=["kube-system"],
            discord_webhook_url="",
        )

        with patch('src.k8s_client.config.load_incluster_config'), \
             patch('src.k8s_client.client.CoreV1Api') as mock_core_v1, \
             patch('src.k8s_client.client.AppsV1Api'), \
             patch('src.k8s_client.tracer'):

            # Mock namespace list
            ns1 = Mock()
            ns1.metadata.name = "default"
            ns2 = Mock()
            ns2.metadata.name = "kube-system"
            ns3 = Mock()
            ns3.metadata.name = "production"

            mock_list_result = Mock()
            mock_list_result.items = [ns1, ns2, ns3]

            k8s = KubernetesClient(config, logger_provider)
            k8s.core_v1.list_namespace.return_value = mock_list_result

            namespaces = k8s._get_namespaces()

            # Should exclude kube-system
            assert "default" in namespaces
            assert "production" in namespaces
            assert "kube-system" not in namespaces

    def test_get_namespace_images_extracts_container_images(self, k8s_client):
        """Test _get_namespace_images extracts images from pods."""
        # Mock pod with containers
        pod = Mock()
        container1 = Mock()
        container1.image = "nginx:1.19"
        container2 = Mock()
        container2.image = "redis:6.0"
        pod.spec.containers = [container1, container2]
        pod.spec.init_containers = None

        mock_list_result = Mock()
        mock_list_result.items = [pod]

        k8s_client.core_v1.list_namespaced_pod.return_value = mock_list_result

        with patch('src.k8s_client.tracer'):
            images = k8s_client._get_namespace_images("default")

            assert "nginx:1.19" in images
            assert "redis:6.0" in images
            assert len(images) == 2

    def test_get_namespace_images_includes_init_containers(self, k8s_client):
        """Test that init containers are also scanned."""
        pod = Mock()

        # Regular container
        regular_container = Mock()
        regular_container.image = "app:1.0"
        pod.spec.containers = [regular_container]

        # Init container
        init_container = Mock()
        init_container.image = "init:1.0"
        pod.spec.init_containers = [init_container]

        mock_list_result = Mock()
        mock_list_result.items = [pod]
        k8s_client.core_v1.list_namespaced_pod.return_value = mock_list_result

        with patch('src.k8s_client.tracer'):
            images = k8s_client._get_namespace_images("default")

            assert "app:1.0" in images
            assert "init:1.0" in images

    def test_get_all_images_combines_namespaces(self, k8s_client):
        """Test that get_all_images combines images from all namespaces."""
        with patch.object(k8s_client, '_get_namespaces', return_value=["ns1", "ns2"]):
            with patch.object(k8s_client, '_get_namespace_images') as mock_get_ns_images:
                # Different images from different namespaces
                def side_effect(ns):
                    if ns == "ns1":
                        return {"app1:1.0", "app2:1.0"}
                    else:
                        return {"app3:1.0"}

                mock_get_ns_images.side_effect = side_effect

                with patch('src.k8s_client.tracer'):
                    images = k8s_client.get_all_images()

                    assert len(images) == 3
                    assert "app1:1.0" in images
                    assert "app2:1.0" in images
                    assert "app3:1.0" in images

    def test_get_all_images_deduplicates(self, k8s_client):
        """Test that duplicate images across namespaces are deduplicated."""
        with patch.object(k8s_client, '_get_namespaces', return_value=["ns1", "ns2"]):
            with patch.object(k8s_client, '_get_namespace_images') as mock_get_ns_images:
                # Same image in both namespaces
                mock_get_ns_images.return_value = {"nginx:1.19"}

                with patch('src.k8s_client.tracer'):
                    images = k8s_client.get_all_images()

                    # Should only have one instance
                    assert len(images) == 1
                    assert "nginx:1.19" in images
