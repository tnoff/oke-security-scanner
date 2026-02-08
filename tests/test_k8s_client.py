"""Tests for k8s_client module."""

from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

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
             patch('src.k8s_client.client.CoreV1Api'), \
             patch('src.k8s_client.client.AppsV1Api'), \
             patch('src.k8s_client.tracer'):
            return KubernetesClient(config, logger_provider)

    @patch('src.k8s_client.tracer')
    @patch('src.k8s_client.client.AppsV1Api')
    @patch('src.k8s_client.client.CoreV1Api')
    @patch('src.k8s_client.config.load_incluster_config')
    def test_init_loads_incluster_config(self, mock_load_config, _mock_core_api, _mock_apps_api, _mock_tracer, config, logger_provider):
        """Test that initialization loads in-cluster config."""
        KubernetesClient(config, logger_provider)
        mock_load_config.assert_called_once()

    def test_get_namespaces_uses_configured_namespaces(self, k8s_client):
        """Test _get_namespaces returns configured namespaces."""
        with patch('src.k8s_client.tracer'):
            namespaces = k8s_client._get_namespaces()
            assert namespaces == ["default", "production"]

    def test_get_namespaces_without_config_discovers_all(self, logger_provider, base_config):
        """Test _get_namespaces discovers namespaces when none configured."""
        base_config.namespaces = []  # Empty - discover all
        base_config.exclude_namespaces = ["kube-system"]

        with patch('src.k8s_client.config.load_incluster_config'), \
             patch('src.k8s_client.client.CoreV1Api'), \
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

            k8s = KubernetesClient(base_config, logger_provider)
            k8s.core_v1.list_namespace.return_value = mock_list_result

            namespaces = k8s._get_namespaces()

            # kube-system should be excluded
            assert "default" in namespaces
            assert "production" in namespaces
            assert "kube-system" not in namespaces


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
        assert image.version.is_semver is True
        assert image.version.major == 1
        assert image.version.minor == 14
        assert image.version.patch == 3

    def test_is_ocir_image(self):
        """Test is_ocir_image property."""
        ocir_image = Image("iad.ocir.io/namespace/repo:v1.0.0")
        docker_image = Image("docker.io/library/nginx:latest")

        assert ocir_image.is_ocir_image is True
        assert docker_image.is_ocir_image is False

    def test_semver_version(self):
        """Test semver version parsing."""
        image = Image("registry.io/repo:v1.2.3")

        assert image.version.is_semver is True
        assert image.version.major == 1
        assert image.version.minor == 2
        assert image.version.patch == 3

    def test_non_semver_version(self):
        """Test non-semver version (arbitrary tag)."""
        image = Image("registry.io/repo:abc123def")

        assert image.version.is_semver is False
        assert image.version.is_githash is False
        assert image.version.tag == "abc123def"

    def test_githash_version(self):
        """Test githash version (7-character alphanumeric)."""
        image = Image("registry.io/repo:abc1234")

        assert image.version.is_semver is False
        assert image.version.is_githash is True
        assert image.version.tag == "abc1234"


class TestImageVersion:
    """Tests for ImageVersion dataclass."""

    def test_semver_version_via_image(self):
        """Test semver version is parsed correctly from Image."""
        # ImageVersion is created by Image's __parse_version method
        image = Image("registry.io/repo:v1.2.3")

        assert image.version.is_semver is True
        assert image.version.major == 1
        assert image.version.minor == 2
        assert image.version.patch == 3

    def test_semver_without_v_prefix_via_image(self):
        """Test semver without v prefix is parsed correctly."""
        image = Image("registry.io/repo:1.2.3")

        assert image.version.is_semver is True
        assert image.version.major == 1
        assert image.version.minor == 2
        assert image.version.patch == 3

    def test_non_semver_arbitrary_tag_via_image(self):
        """Test non-semver arbitrary tag."""
        image = Image("registry.io/repo:abc123def456")

        assert image.version.is_semver is False
        assert image.version.is_githash is False
        assert image.version.tag == "abc123def456"

    def test_githash_via_image(self):
        """Test 7-character githash is detected correctly."""
        image = Image("registry.io/repo:a1b2c3d")

        assert image.version.is_semver is False
        assert image.version.is_githash is True
        assert image.version.tag == "a1b2c3d"

    def test_version_comparison(self):
        """Test version comparison operators."""
        # Create versions via Image parsing
        img1 = Image("registry.io/repo:1.0.0")
        img2 = Image("registry.io/repo:2.0.0")
        img1_copy = Image("registry.io/repo:1.0.0")

        assert img1.version < img2.version
        assert img2.version > img1.version
        assert img1.version == img1_copy.version
        assert img1.version != img2.version

    def test_version_comparison_minor(self):
        """Test minor version comparison."""
        img1_1 = Image("registry.io/repo:1.1.0")
        img1_2 = Image("registry.io/repo:1.2.0")

        assert img1_1.version < img1_2.version
        assert img1_2.version > img1_1.version

    def test_version_comparison_patch(self):
        """Test patch version comparison."""
        img1_0_1 = Image("registry.io/repo:1.0.1")
        img1_0_2 = Image("registry.io/repo:1.0.2")

        assert img1_0_1.version < img1_0_2.version
        assert img1_0_2.version > img1_0_1.version

    def test_str_representation(self):
        """Test string representation of versions."""
        semver_img = Image("registry.io/repo:v1.2.3")
        commit_img = Image("registry.io/repo:abc1234")

        assert str(semver_img.version) == "1.2.3"
        assert str(commit_img.version) == "abc1234"

    def test_image_comparison_with_created_at(self):
        """Test Image comparison uses created_at for non-semver images."""
        img1 = Image("registry.io/repo:abc1234", created_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        img2 = Image("registry.io/repo:def5678", created_at=datetime(2024, 2, 1, tzinfo=timezone.utc))

        assert img1 < img2
        assert img2 > img1

    def test_image_comparison_semver_vs_semver(self):
        """Test Image comparison uses semver for semver images."""
        img1 = Image("registry.io/repo:v1.0.0")
        img2 = Image("registry.io/repo:v2.0.0")

        assert img1 < img2
        assert img2 > img1
