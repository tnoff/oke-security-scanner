"""Tests for registry_client module."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from src.registry_client import RegistryClient
from src.config import Config


class TestRegistryClient:
    """Tests for RegistryClient class."""

    @pytest.fixture
    def config(self):
        """Create test config."""
        return Config(
            oci_registry="test.ocir.io",
            oci_username="testuser",
            oci_token="testtoken",
            oci_namespace="testnamespace",
            otlp_endpoint="http://localhost:4318",
            otlp_insecure=True,
            otlp_traces_enabled=True,
            otlp_metrics_enabled=True,
            otlp_logs_enabled=True,
            trivy_severity="CRITICAL,HIGH",
            trivy_timeout=300,
            namespaces=[],
            exclude_namespaces=[],
            discord_webhook_url="",
        )

    @patch('src.registry_client.oci')
    def test_init_with_oci_sdk(self, mock_oci, config):
        """Test RegistryClient initialization with OCI SDK."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_artifacts_client = Mock()
        mock_identity_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = mock_identity_client

        client = RegistryClient(config)

        assert client.artifacts_client == mock_artifacts_client
        assert client.identity_client == mock_identity_client
        assert client.oci_config == mock_config
        mock_oci.config.from_file.assert_called_once()

    @patch('src.registry_client.oci')
    def test_init_without_oci_sdk(self, mock_oci, config):
        """Test RegistryClient initialization when OCI SDK fails."""
        mock_oci.config.from_file.side_effect = Exception("No config file")

        client = RegistryClient(config)

        assert client.artifacts_client is None
        assert client.identity_client is None
        assert client.oci_config is None

    def test_parse_image_name_with_registry(self, config):
        """Test parsing image name with explicit registry."""
        registry, repository, tag = RegistryClient.parse_image_name(
            "iad.ocir.io/namespace/repo:v1.0.0"
        )
        assert registry == "iad.ocir.io"
        assert repository == "namespace/repo"
        assert tag == "v1.0.0"

    def test_parse_image_name_without_tag(self, config):
        """Test parsing image name without tag."""
        registry, repository, tag = RegistryClient.parse_image_name(
            "docker.io/library/nginx"
        )
        assert registry == "docker.io"
        assert repository == "library/nginx"
        assert tag == "latest"

    def test_is_ocir_image(self, config):
        """Test is_ocir_image check."""
        with patch('src.registry_client.oci'):
            client = RegistryClient(config)
            assert client.is_ocir_image("test.ocir.io") is True
            assert client.is_ocir_image("docker.io") is False

    @patch('src.registry_client.oci')
    def test_get_tenancy_id(self, mock_oci, config):
        """Test _get_tenancy_id method."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        client = RegistryClient(config)
        tenancy_id = client._get_tenancy_id()

        assert tenancy_id == 'ocid1.tenancy.test'

    @patch('src.registry_client.oci')
    def test_get_tenancy_id_no_config(self, mock_oci, config):
        """Test _get_tenancy_id when no config available."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        tenancy_id = client._get_tenancy_id()

        assert tenancy_id is None

    @patch('src.registry_client.oci')
    def test_list_all_compartments(self, mock_oci, config):
        """Test _list_all_compartments method."""
        # Setup mocks
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_identity_client = Mock()
        mock_oci.identity.IdentityClient.return_value = mock_identity_client
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()

        # Mock compartment list response
        mock_compartment1 = Mock()
        mock_compartment1.id = 'ocid1.compartment.1'
        mock_compartment1.lifecycle_state = 'ACTIVE'

        mock_compartment2 = Mock()
        mock_compartment2.id = 'ocid1.compartment.2'
        mock_compartment2.lifecycle_state = 'ACTIVE'

        mock_compartment3 = Mock()
        mock_compartment3.id = 'ocid1.compartment.3'
        mock_compartment3.lifecycle_state = 'DELETED'  # Should be filtered out

        mock_response = Mock()
        mock_response.data = [mock_compartment1, mock_compartment2, mock_compartment3]
        mock_identity_client.list_compartments.return_value = mock_response

        client = RegistryClient(config)
        compartments = client._list_all_compartments()

        # Should include tenancy + 2 active compartments
        assert len(compartments) == 3
        assert 'ocid1.tenancy.test' in compartments
        assert 'ocid1.compartment.1' in compartments
        assert 'ocid1.compartment.2' in compartments
        assert 'ocid1.compartment.3' not in compartments

        mock_identity_client.list_compartments.assert_called_once_with(
            compartment_id='ocid1.tenancy.test',
            compartment_id_in_subtree=True,
            access_level="ACCESSIBLE"
        )

    @patch('src.registry_client.oci')
    def test_list_all_compartments_failure(self, mock_oci, config):
        """Test _list_all_compartments when API call fails."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_identity_client = Mock()
        mock_identity_client.list_compartments.side_effect = Exception("API Error")
        mock_oci.identity.IdentityClient.return_value = mock_identity_client
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()

        client = RegistryClient(config)
        compartments = client._list_all_compartments()

        # Should fall back to just tenancy
        assert compartments == ['ocid1.tenancy.test']

    @patch('src.registry_client.oci')
    def test_find_repository_compartment_cached(self, mock_oci, config):
        """Test _find_repository_compartment with cached result."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        client = RegistryClient(config)
        # Pre-populate cache
        client._repository_compartment_cache['test/repo'] = 'ocid1.compartment.cached'

        compartment_id = client._find_repository_compartment('test/repo')

        assert compartment_id == 'ocid1.compartment.cached'
        # Should not call any APIs when cached

    @patch('src.registry_client.oci')
    def test_find_repository_compartment_search(self, mock_oci, config):
        """Test _find_repository_compartment by searching compartments."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        # Mock artifacts client
        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client

        # Mock identity client
        mock_identity_client = Mock()
        mock_oci.identity.IdentityClient.return_value = mock_identity_client

        # Mock compartment list
        mock_compartment = Mock()
        mock_compartment.id = 'ocid1.compartment.apps'
        mock_compartment.lifecycle_state = 'ACTIVE'
        mock_comp_response = Mock()
        mock_comp_response.data = [mock_compartment]
        mock_identity_client.list_compartments.return_value = mock_comp_response

        # Create proper ServiceError exception class
        class ServiceError(Exception):
            def __init__(self, status, message):
                super().__init__(message)
                self.status = status
                self.message = message

        mock_oci.exceptions.ServiceError = ServiceError

        client = RegistryClient(config)

        # Manually set up the exception handling
        with patch.object(client.artifacts_client, 'list_container_images') as mock_list:
            # Second call succeeds
            second_response = Mock()
            second_item = Mock()
            second_response.data.items = [second_item]

            def side_effect(*args, **kwargs):
                compartment = kwargs.get('compartment_id')
                if compartment == 'ocid1.tenancy.test':
                    raise ServiceError(404, 'Not found')
                else:
                    return second_response

            mock_list.side_effect = side_effect

            compartment_id = client._find_repository_compartment('test/repo')

            assert compartment_id == 'ocid1.compartment.apps'
            # Should be cached now
            assert client._repository_compartment_cache['test/repo'] == 'ocid1.compartment.apps'

    @patch('src.registry_client.oci')
    def test_find_repository_compartment_not_found(self, mock_oci, config):
        """Test _find_repository_compartment when repository doesn't exist."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_identity_client = Mock()
        mock_oci.identity.IdentityClient.return_value = mock_identity_client

        # Mock compartment list - just tenancy
        mock_comp_response = Mock()
        mock_comp_response.data = []
        mock_identity_client.list_compartments.return_value = mock_comp_response

        # Create proper ServiceError exception class
        class ServiceError(Exception):
            def __init__(self, status, message):
                super().__init__(message)
                self.status = status
                self.message = message

        mock_oci.exceptions.ServiceError = ServiceError

        # Mock 404 for all searches
        with patch.object(mock_artifacts_client, 'list_container_images') as mock_list:
            mock_list.side_effect = ServiceError(404, 'Not found')

            client = RegistryClient(config)
            compartment_id = client._find_repository_compartment('nonexistent/repo')

            assert compartment_id is None

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk method."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = Mock()

        # Mock finding compartment
        client = RegistryClient(config)
        client._repository_compartment_cache['test/repo'] = 'ocid1.compartment.apps'

        # Mock image list response
        mock_image1 = Mock()
        mock_image1.version = 'v1.0.0'
        mock_image1.time_created = datetime(2024, 1, 1)
        mock_image1.digest = 'sha256:abc123'

        mock_image2 = Mock()
        mock_image2.version = 'v1.1.0'
        mock_image2.time_created = datetime(2024, 2, 1)
        mock_image2.digest = 'sha256:def456'

        mock_response = Mock()
        mock_response.data.items = [mock_image1, mock_image2]
        mock_artifacts_client.list_container_images.return_value = mock_response

        images = client._get_ocir_images_via_sdk('test/repo')

        assert len(images) == 2
        assert images[0]['tag'] == 'v1.0.0'
        assert images[0]['created_at'] == datetime(2024, 1, 1)
        assert images[0]['digest'] == 'sha256:abc123'
        assert images[1]['tag'] == 'v1.1.0'

        # Should be cached
        assert 'test/repo' in client._ocir_image_cache

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk_cached(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk with cached data."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = Mock()

        client = RegistryClient(config)

        # Pre-populate cache
        cached_data = [
            {'tag': 'cached', 'created_at': datetime(2024, 1, 1), 'digest': 'sha256:cached'}
        ]
        client._ocir_image_cache['test/repo'] = cached_data

        images = client._get_ocir_images_via_sdk('test/repo')

        assert images == cached_data
        # Should not call API when cached
        mock_artifacts_client.list_container_images.assert_not_called()

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk_no_compartment(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk when compartment not found."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client

        mock_identity_client = Mock()
        mock_comp_response = Mock()
        mock_comp_response.data = []
        mock_identity_client.list_compartments.return_value = mock_comp_response
        mock_oci.identity.IdentityClient.return_value = mock_identity_client

        # Create proper ServiceError exception class
        class ServiceError(Exception):
            def __init__(self, status, message):
                super().__init__(message)
                self.status = status
                self.message = message

        mock_oci.exceptions.ServiceError = ServiceError

        # Mock 404 for compartment search
        with patch.object(mock_artifacts_client, 'list_container_images') as mock_list:
            mock_list.side_effect = ServiceError(404, 'Not found')

            client = RegistryClient(config)
            images = client._get_ocir_images_via_sdk('nonexistent/repo')

            assert images == []

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk_no_client(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk when OCI client unavailable."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        images = client._get_ocir_images_via_sdk('test/repo')

        assert images == []
