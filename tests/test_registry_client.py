"""Tests for registry_client module."""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta
from src.registry_client import RegistryClient, UpdateInfo, CleanupRecommendation
from src.k8s_client import Image


class TestRegistryClient:
    """Tests for RegistryClient class."""

    @pytest.fixture
    def config(self, base_config):
        """Use the shared base_config fixture."""
        return base_config

    @patch('src.registry_client.oci')
    def test_init_with_oci_sdk(self, mock_oci, config):
        """Test RegistryClient initialization with OCI SDK."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_artifacts_client = Mock()
        mock_identity_client = Mock()
        mock_object_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = mock_identity_client
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)

        assert client.artifacts_client == mock_artifacts_client
        assert client.identity_client == mock_identity_client
        assert client.object_client == mock_object_client
        assert client.oci_config == mock_config
        mock_oci.config.from_file.assert_called_once()

    @patch('src.registry_client.oci')
    def test_init_without_oci_sdk(self, mock_oci, config):
        """Test RegistryClient initialization when OCI SDK fails."""
        mock_oci.config.from_file.side_effect = Exception("No config file")

        client = RegistryClient(config)

        assert client.artifacts_client is None
        assert client.identity_client is None
        assert client.object_client is None
        assert client.oci_config is None

    @patch('src.registry_client.oci')
    def test_oci_namespace_property_fetches_from_object_storage(self, mock_oci, config):
        """Test oci_namespace property fetches namespace from Object Storage API."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)
        namespace = client.oci_namespace

        assert namespace == 'testnamespace'
        mock_object_client.get_namespace.assert_called_once()

    @patch('src.registry_client.oci')
    def test_oci_namespace_property_caches_result(self, mock_oci, config):
        """Test oci_namespace property caches the result after first fetch."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)

        # First call
        namespace1 = client.oci_namespace
        # Second call
        namespace2 = client.oci_namespace

        assert namespace1 == 'testnamespace'
        assert namespace2 == 'testnamespace'
        # Should only call API once
        assert mock_object_client.get_namespace.call_count == 1

    @patch('src.registry_client.oci')
    def test_oci_namespace_property_returns_none_without_client(self, mock_oci, config):
        """Test oci_namespace property returns None when object client unavailable."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        namespace = client.oci_namespace

        assert namespace is None

    @patch('src.registry_client.oci')
    def test_oci_registry_property_caches_result(self, mock_oci, config):
        """Test oci_registry property caches the result after first derivation."""
        mock_config = {'tenancy': 'ocid1.tenancy.test', 'region': 'us-ashburn-1'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)
        # Pre-populate cache
        client._oci_registry = 'iad.ocir.io'

        # First call
        registry1 = client.oci_registry
        # Second call
        registry2 = client.oci_registry

        assert registry1 == 'iad.ocir.io'
        assert registry2 == 'iad.ocir.io'

    @patch('src.registry_client.oci')
    def test_oci_registry_property_returns_none_without_config(self, mock_oci, config):
        """Test oci_registry property returns None when OCI config unavailable."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        registry = client.oci_registry

        assert registry is None

    @patch('src.registry_client.oci')
    def test_strip_namespace_prefix_with_namespace(self, mock_oci, config):
        """Test _strip_namespace_prefix strips namespace prefix."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)

        # Should strip namespace prefix
        assert client._strip_namespace_prefix('testnamespace/myapp') == 'myapp'
        assert client._strip_namespace_prefix('testnamespace/my-app') == 'my-app'

    @patch('src.registry_client.oci')
    def test_strip_namespace_prefix_without_namespace(self, mock_oci, config):
        """Test _strip_namespace_prefix leaves repo unchanged if no namespace prefix."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)

        # Should not change if no namespace prefix
        assert client._strip_namespace_prefix('myapp') == 'myapp'
        assert client._strip_namespace_prefix('my-app') == 'my-app'

    @patch('src.registry_client.oci')
    def test_strip_namespace_prefix_different_namespace(self, mock_oci, config):
        """Test _strip_namespace_prefix leaves repo unchanged if different namespace."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)

        # Should not change if different namespace prefix
        assert client._strip_namespace_prefix('othernamespace/myapp') == 'othernamespace/myapp'

    @patch('src.registry_client.oci')
    def test_strip_namespace_prefix_fallback_without_namespace(self, mock_oci, config):
        """Test _strip_namespace_prefix fallback when namespace unavailable."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)

        # Should fall back to taking last part after '/'
        assert client._strip_namespace_prefix('anyprefix/myapp') == 'myapp'
        assert client._strip_namespace_prefix('myapp') == 'myapp'

    @patch('src.registry_client.oci')
    def test_get_tenancy_id(self, mock_oci, config):
        """Test _get_tenancy_id method."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

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
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_identity_client = Mock()
        mock_oci.identity.IdentityClient.return_value = mock_identity_client
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        # Mock compartment list response
        mock_compartment1 = Mock()
        mock_compartment1.id = 'ocid1.compartment.1'
        mock_compartment1.lifecycle_state = 'ACTIVE'

        mock_compartment2 = Mock()
        mock_compartment2.id = 'ocid1.compartment.2'
        mock_compartment2.lifecycle_state = 'ACTIVE'

        mock_compartment3 = Mock()
        mock_compartment3.id = 'ocid1.compartment.3'
        mock_compartment3.lifecycle_state = 'DELETED'

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

    @patch('src.registry_client.oci')
    def test_find_repository_compartment_cached(self, mock_oci, config):
        """Test _find_repository_compartment with cached result."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)
        # Pre-populate cache
        client._repository_compartment_cache['test-repo'] = 'ocid1.compartment.cached'

        compartment_id = client._find_repository_compartment('test-repo')

        assert compartment_id == 'ocid1.compartment.cached'

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk method."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)
        # Pre-populate compartment cache
        client._repository_compartment_cache['myapp'] = 'ocid1.compartment.apps'

        # Mock image list response
        mock_image1 = Mock()
        mock_image1.version = 'v1.0.0'
        mock_image1.time_created = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_image1.id = 'ocid1.image.1'

        mock_image2 = Mock()
        mock_image2.version = 'v1.1.0'
        mock_image2.time_created = datetime(2024, 2, 1, tzinfo=timezone.utc)
        mock_image2.id = 'ocid1.image.2'

        mock_list_response = Mock()
        mock_list_response.data.items = [mock_image1, mock_image2]
        mock_artifacts_client.list_container_images.return_value = mock_list_response

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        images = client._get_ocir_images_via_sdk(image)

        assert len(images) == 2
        assert images[0].tag == 'v1.0.0'
        assert images[1].tag == 'v1.1.0'

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk_cached(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk with cached data."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)

        # Pre-populate cache
        cached_image = Image('test.ocir.io/testnamespace/myapp:cached')
        client._ocir_image_cache['testnamespace/myapp'] = [cached_image]

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        images = client._get_ocir_images_via_sdk(image)

        assert images == [cached_image]
        # Should not call API when cached
        mock_artifacts_client.list_container_images.assert_not_called()

    @patch('src.registry_client.oci')
    def test_get_ocir_images_via_sdk_no_client(self, mock_oci, config):
        """Test _get_ocir_images_via_sdk when OCI client unavailable."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        images = client._get_ocir_images_via_sdk(image)

        assert images == []

    @patch('src.registry_client.oci')
    def test_check_image_updates_skips_latest(self, mock_oci, config):
        """Test check_image_updates skips 'latest' tag."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)
        image = Image('test.ocir.io/testnamespace/myapp:latest')

        result = client.check_image_updates(image)

        assert result is None

    @patch('src.registry_client.oci')
    def test_check_image_updates_returns_update_info(self, mock_oci, config):
        """Test check_image_updates returns UpdateInfo when update available."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)
        client._repository_compartment_cache['myapp'] = 'ocid1.compartment.apps'

        # Set up cached images with older and newer versions
        old_image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        new_image = Image('test.ocir.io/testnamespace/myapp:v2.0.0')
        client._ocir_image_cache['testnamespace/myapp'] = [old_image, new_image]

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        result = client.check_image_updates(image)

        assert result is not None
        assert isinstance(result, UpdateInfo)
        assert str(result.current) == '1.0.0'
        assert str(result.latest) == '2.0.0'

    @patch('src.registry_client.oci')
    def test_get_old_images_returns_cleanup_recommendations(self, mock_oci, config):
        """Test get_old_images returns CleanupRecommendation for old images."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)
        client._repository_compartment_cache['myapp'] = 'ocid1.compartment.apps'

        # Create old commit hash images
        now = datetime.now(timezone.utc)
        cached_images = []
        for i in range(10):
            img = Image(
                f'test.ocir.io/testnamespace/myapp:commit{i}',
                ocid=f'ocid1.image.{i}',
                created_at=now - timedelta(days=i)
            )
            cached_images.append(img)

        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # Current image in use
        images = [Image('test.ocir.io/testnamespace/myapp:commit0')]

        recommendations = client.get_old_images(images, keep_count=5)

        assert len(recommendations) == 1
        rec = recommendations[0]
        assert isinstance(rec, CleanupRecommendation)
        assert rec.repository == 'testnamespace/myapp'
        # Should have 4 images to delete (10 - 1 current - 5 keep = 4)
        assert len(rec.tags_to_delete) == 4

    @patch('src.registry_client.oci')
    def test_delete_ocir_images(self, mock_oci, config):
        """Test delete_ocir_images deletes images via SDK."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)

        # Create cleanup recommendations
        img1 = Image('test.ocir.io/testnamespace/myapp:old1', ocid='ocid1.image.1')
        img2 = Image('test.ocir.io/testnamespace/myapp:old2', ocid='ocid1.image.2')
        recommendations = [
            CleanupRecommendation(
                registry='test.ocir.io',
                repository='testnamespace/myapp',
                tags_to_delete=[img1, img2]
            )
        ]

        deleted = client.delete_ocir_images(recommendations)

        assert len(deleted) == 2
        assert mock_artifacts_client.delete_container_image.call_count == 2
        mock_artifacts_client.delete_container_image.assert_any_call('ocid1.image.1')
        mock_artifacts_client.delete_container_image.assert_any_call('ocid1.image.2')

    @patch('src.registry_client.oci')
    def test_delete_ocir_images_no_client(self, mock_oci, config):
        """Test delete_ocir_images returns empty when no SDK client."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        recommendations = []

        result = client.delete_ocir_images(recommendations)

        assert result == {}
