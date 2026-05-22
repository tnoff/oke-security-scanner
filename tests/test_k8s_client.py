"""Tests for k8s_client module."""

from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest
from kubernetes.client.rest import ApiException

from src.k8s_client import KubernetesClient, Image


class TestKubernetesClient:
    """Tests for KubernetesClient class."""

    @pytest.fixture
    def config(self, base_config):
        """Use the shared base_config fixture with namespaces."""
        base_config.namespaces = ["default", "production"]
        return base_config

    @pytest.fixture
    def logger_provider(self):
        """Create mock logger provider."""
        return Mock()

    @pytest.fixture
    def k8s_client(self, config, logger_provider):
        """Create a KubernetesClient instance."""
        with patch('src.k8s_client.config.load_incluster_config'), \
             patch('src.k8s_client.client.CoreV1Api'):
            return KubernetesClient(config, logger_provider)

    @patch('src.k8s_client.client.CoreV1Api')
    @patch('src.k8s_client.config.load_incluster_config')
    def test_init_loads_incluster_config(self, mock_load_config, _mock_core_api, config, logger_provider):
        """Test that initialization loads in-cluster config."""
        KubernetesClient(config, logger_provider)
        mock_load_config.assert_called_once()

    @patch('src.k8s_client.client.CoreV1Api')
    @patch('src.k8s_client.config.load_kube_config')
    @patch('src.k8s_client.config.load_incluster_config')
    def test_init_falls_back_to_kubeconfig(self, mock_incluster, mock_kubeconfig, _mock_core_api, config, logger_provider):
        """ConfigException from in-cluster config triggers load_kube_config fallback."""
        from kubernetes.config import ConfigException
        mock_incluster.side_effect = ConfigException("not running in cluster")

        KubernetesClient(config, logger_provider)

        mock_incluster.assert_called_once()
        mock_kubeconfig.assert_called_once()

    @patch('src.k8s_client.client.CoreV1Api')
    @patch('src.k8s_client.config.load_incluster_config')
    def test_init_mirrors_authorization_to_bearertoken(self, mock_load_config, _mock_core_api, config, logger_provider):
        """kubernetes==36 stores the bearer token under api_key['authorization'] but the
        generated API methods look it up under 'BearerToken'. KubernetesClient.__init__
        must mirror the value across so outgoing requests carry an Authorization header."""
        from kubernetes import client as k8s_client_mod

        original = k8s_client_mod.Configuration.get_default_copy()
        try:
            def populate_auth_like_v36():
                cfg = k8s_client_mod.Configuration.get_default_copy()
                cfg.api_key = {'authorization': 'bearer fake-token'}
                k8s_client_mod.Configuration.set_default(cfg)
            mock_load_config.side_effect = populate_auth_like_v36

            KubernetesClient(config, logger_provider)

            final = k8s_client_mod.Configuration.get_default_copy()
            assert final.api_key.get('BearerToken') == 'bearer fake-token'
            assert final.api_key.get('authorization') == 'bearer fake-token'
        finally:
            k8s_client_mod.Configuration.set_default(original)

    @patch('src.k8s_client.client.CoreV1Api')
    @patch('src.k8s_client.config.load_incluster_config')
    def test_init_does_not_overwrite_existing_bearertoken(self, mock_load_config, _mock_core_api, config, logger_provider):
        """If the loader already populated 'BearerToken' (e.g. on a future fixed client),
        the mirror step must leave it alone."""
        from kubernetes import client as k8s_client_mod

        original = k8s_client_mod.Configuration.get_default_copy()
        try:
            def populate_both():
                cfg = k8s_client_mod.Configuration.get_default_copy()
                cfg.api_key = {'authorization': 'bearer old', 'BearerToken': 'bearer new'}
                k8s_client_mod.Configuration.set_default(cfg)
            mock_load_config.side_effect = populate_both

            KubernetesClient(config, logger_provider)

            assert k8s_client_mod.Configuration.get_default_copy().api_key['BearerToken'] == 'bearer new'
        finally:
            k8s_client_mod.Configuration.set_default(original)

    def test_get_namespaces_uses_configured_namespaces(self, k8s_client):
        """Test _get_namespaces returns configured namespaces."""
        namespaces = k8s_client._get_namespaces()
        assert namespaces == ["default", "production"]

    def test_get_namespaces_without_config_discovers_all(self, logger_provider, base_config):
        """Test _get_namespaces discovers namespaces when none configured."""
        base_config.namespaces = []  # Empty - discover all
        base_config.exclude_namespaces = ["kube-system"]

        with patch('src.k8s_client.config.load_incluster_config'), \
             patch('src.k8s_client.client.CoreV1Api'):

            # Mock namespace list
            ns1 = Mock()
            ns1.metadata.name = "default"
            ns2 = Mock()
            ns2.metadata.name = "kube-system"
            ns3 = Mock()
            ns3.metadata.name = "production"

            mock_list_result = Mock()
            mock_list_result.items = [ns1, ns2, ns3]

            k8s = KubernetesClient(base_config, logger_provider)
            k8s.core_v1.list_namespace.return_value = mock_list_result

            namespaces = k8s._get_namespaces()

            # kube-system should be excluded
            assert "default" in namespaces
            assert "production" in namespaces
            assert "kube-system" not in namespaces

    def _make_pod(self, containers=(), init_containers=()):
        """Build a pod mock with the given container and init-container images."""
        pod = Mock()
        pod.spec.containers = [Mock(image=img) for img in containers] if containers else None
        pod.spec.init_containers = [Mock(image=img) for img in init_containers] if init_containers else None
        return pod

    def test_get_namespace_images_collects_regular_and_init_containers(self, k8s_client):
        """_get_namespace_images extracts images from both regular and init containers."""
        pod_a = self._make_pod(
            containers=["docker.io/library/nginx:1.27"],
            init_containers=["docker.io/library/busybox:1.36"],
        )
        pod_b = self._make_pod(containers=["iad.ocir.io/ns/app:v1.0.0"])

        list_result = Mock()
        list_result.items = [pod_a, pod_b]
        k8s_client.core_v1.list_namespaced_pod.return_value = list_result

        images = k8s_client._get_namespace_images("default")

        full_names = {img.full_name for img in images}
        assert full_names == {
            "docker.io/library/nginx:1.27",
            "docker.io/library/busybox:1.36",
            "iad.ocir.io/ns/app:v1.0.0",
        }

    def test_get_namespace_images_returns_empty_on_api_exception(self, k8s_client):
        """_get_namespace_images logs and returns an empty set when the pod list fails."""
        k8s_client.core_v1.list_namespaced_pod.side_effect = ApiException(status=403, reason="Forbidden")

        images = k8s_client._get_namespace_images("restricted")

        assert images == set()

    def test_get_all_images_aggregates_across_namespaces(self, k8s_client):
        """get_all_images merges images from each configured namespace."""
        def list_pods(namespace):
            pod = Mock()
            if namespace == "default":
                pod.spec.containers = [Mock(image="docker.io/library/nginx:1.27")]
                pod.spec.init_containers = None
            else:
                pod.spec.containers = [Mock(image="iad.ocir.io/ns/app:v1.0.0")]
                pod.spec.init_containers = None
            result = Mock()
            result.items = [pod]
            return result

        k8s_client.core_v1.list_namespaced_pod.side_effect = list_pods

        images = k8s_client.get_all_images()

        full_names = {img.full_name for img in images}
        assert full_names == {
            "docker.io/library/nginx:1.27",
            "iad.ocir.io/ns/app:v1.0.0",
        }

    def test_get_all_images_reraises_namespace_list_failure(self, logger_provider, base_config):
        """get_all_images propagates an ApiException raised by namespace discovery."""
        base_config.namespaces = []
        base_config.exclude_namespaces = []

        with patch('src.k8s_client.config.load_incluster_config'), \
             patch('src.k8s_client.client.CoreV1Api'):
            k8s = KubernetesClient(base_config, logger_provider)

        k8s.core_v1.list_namespace.side_effect = ApiException(status=500, reason="Boom")

        with pytest.raises(ApiException):
            k8s.get_all_images()


class TestImage:
    """Tests for Image dataclass."""

    def test_parse_image_with_registry_and_tag(self):
        """Test parsing image with explicit registry and tag."""
        image = Image("iad.ocir.io/namespace/repo:v1.0.0")

        assert image.registry == "iad.ocir.io"
        assert image.repo_name == "namespace/repo"
        assert image.tag == "v1.0.0"
        assert image.full_name == "iad.ocir.io/namespace/repo:v1.0.0"

    def test_parse_image_with_latest_tag(self):
        """Test parsing image with latest tag."""
        image = Image("docker.io/library/nginx:latest")

        assert image.registry == "docker.io"
        assert image.repo_name == "library/nginx"
        assert image.tag == "latest"

    def test_parse_image_strips_digest(self):
        """Test parsing image with digest (@sha256:...) strips it from tag."""
        image = Image("registry.k8s.io/ingress-nginx/controller:v1.14.3@sha256:abc123def456")

        assert image.registry == "registry.k8s.io"
        assert image.repo_name == "ingress-nginx/controller"
        assert image.tag == "v1.14.3"

    def test_is_ocir_image(self):
        """Test is_ocir_image property."""
        ocir_image = Image("iad.ocir.io/namespace/repo:v1.0.0")
        docker_image = Image("docker.io/library/nginx:latest")

        assert ocir_image.is_ocir_image is True
        assert docker_image.is_ocir_image is False

    def test_image_comparison_with_created_at(self):
        """Test Image comparison uses created_at when present."""
        img1 = Image("registry.io/repo:abc1234", created_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        img2 = Image("registry.io/repo:def5678", created_at=datetime(2024, 2, 1, tzinfo=timezone.utc))

        assert img1 < img2
        assert img2 > img1

    def test_image_comparison_falls_back_to_full_name(self):
        """Test Image comparison falls back to full_name when created_at missing."""
        img1 = Image("registry.io/repo:a")
        img2 = Image("registry.io/repo:b")

        assert img1 < img2
