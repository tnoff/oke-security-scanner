"""Tests for registry_client module."""

import json
import pytest
import requests
from unittest.mock import Mock, patch, mock_open
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
        mock_image1.digest = 'sha256:aaa111'

        mock_image2 = Mock()
        mock_image2.version = 'v1.1.0'
        mock_image2.time_created = datetime(2024, 2, 1, tzinfo=timezone.utc)
        mock_image2.id = 'ocid1.image.2'
        mock_image2.digest = 'sha256:bbb222'

        mock_image3 = Mock()
        mock_image3.version = None
        mock_image3.digest = 'sha256:abc123def456'
        mock_image3.time_created = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_image3.id = 'ocid1.image.3'

        mock_list_response = Mock()
        mock_list_response.data = [mock_image1, mock_image2, mock_image3]
        mock_oci.pagination.list_call_get_all_results.return_value = mock_list_response

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        images = client._get_ocir_images_via_sdk(image)

        assert len(images) == 3
        assert images[0].tag == 'v1.0.0'
        assert images[1].tag == 'v1.1.0'
        # Untagged platform manifest uses digest as synthetic tag
        assert 'sha256:abc123def456' in images[2].full_name
        assert images[0].digest == 'sha256:aaa111'
        assert images[1].digest == 'sha256:bbb222'

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

        result = client.check_image_updates([image])

        assert len(result) == 0

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
        result = client.check_image_updates([image])

        assert result is not None
        assert isinstance(result[0], UpdateInfo)
        assert str(result[0].current) == '1.0.0'
        assert str(result[0].latest) == '2.0.0'

    @patch('src.registry_client.oci')
    def test_get_old_ocir_images_returns_cleanup_recommendations(self, mock_oci, config):
        """Test get_old_ocir_images returns CleanupRecommendation for old images."""
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

        # Create old githash images (7-character alphanumeric tags)
        now = datetime.now(timezone.utc)
        cached_images = []
        for i in range(10):
            img = Image(
                f'test.ocir.io/testnamespace/myapp:abc{i:04d}',
                ocid=f'ocid1.image.{i}',
                created_at=now - timedelta(days=i)
            )
            cached_images.append(img)

        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # Current image in use
        images = [Image('test.ocir.io/testnamespace/myapp:abc0000')]

        recommendations = client.get_old_ocir_images(images, keep_count=5)

        assert len(recommendations) == 1
        rec = recommendations[0]
        assert isinstance(rec, CleanupRecommendation)
        assert rec.repository == 'testnamespace/myapp'
        # Should have 4 images to delete (10 - 1 current - 5 keep = 4)
        assert len(rec.tags_to_delete) == 4

    @patch('src.registry_client.oci')
    def test_get_old_ocir_images_includes_all_tag_types(self, mock_oci, config):
        """Test get_old_ocir_images includes semver, githash, and arbitrary tags in cleanup."""
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

        now = datetime.now(timezone.utc)
        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:abc1234', ocid='ocid1.image.1', created_at=now - timedelta(days=10)),
            Image('test.ocir.io/testnamespace/myapp:v1.0.0', ocid='ocid1.image.2', created_at=now - timedelta(days=9)),
            Image('test.ocir.io/testnamespace/myapp:my-custom-tag', ocid='ocid1.image.3', created_at=now - timedelta(days=8)),
            Image('test.ocir.io/testnamespace/myapp:dev-build-42', ocid='ocid1.image.4', created_at=now - timedelta(days=7)),
            Image('test.ocir.io/testnamespace/myapp:deployed', ocid='ocid1.image.5', created_at=now - timedelta(days=1)),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # 'deployed' is the currently running image
        images = [Image('test.ocir.io/testnamespace/myapp:deployed')]

        recommendations = client.get_old_ocir_images(images, keep_count=1)

        assert len(recommendations) == 1
        rec = recommendations[0]
        deleted_tags = {img.tag for img in rec.tags_to_delete}
        # 5 total - 1 deployed - 1 keep = 3 to delete (the 3 oldest)
        assert len(rec.tags_to_delete) == 3
        assert 'abc1234' in deleted_tags
        assert 'v1.0.0' in deleted_tags
        assert 'my-custom-tag' in deleted_tags
        # The kept image (newest non-deployed) and deployed should not be deleted
        assert 'dev-build-42' not in deleted_tags
        assert 'deployed' not in deleted_tags

    @patch('src.registry_client.oci')
    def test_get_old_ocir_images_excludes_latest_and_deployed(self, mock_oci, config):
        """Test get_old_ocir_images always excludes 'latest' tag and currently deployed image."""
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

        now = datetime.now(timezone.utc)
        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:latest', ocid='ocid1.image.0', created_at=now),
            Image('test.ocir.io/testnamespace/myapp:abc1234', ocid='ocid1.image.1', created_at=now - timedelta(days=10)),
            Image('test.ocir.io/testnamespace/myapp:old-tag', ocid='ocid1.image.2', created_at=now - timedelta(days=9)),
            Image('test.ocir.io/testnamespace/myapp:deployed', ocid='ocid1.image.3', created_at=now - timedelta(days=1)),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        images = [Image('test.ocir.io/testnamespace/myapp:deployed')]

        recommendations = client.get_old_ocir_images(images, keep_count=0)

        assert len(recommendations) == 1
        rec = recommendations[0]
        deleted_tags = {img.tag for img in rec.tags_to_delete}
        # 'latest' and 'deployed' must never be deleted
        assert 'latest' not in deleted_tags
        assert 'deployed' not in deleted_tags
        # The remaining images should be marked for deletion
        assert 'abc1234' in deleted_tags
        assert 'old-tag' in deleted_tags

    @patch('src.registry_client.oci')
    def test_get_orphaned_manifests_basic(self, mock_oci, config):
        """Test orphan detection: platform manifests not referenced by any normal tag's manifest list are orphans."""
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

        now = datetime.now(timezone.utc)
        build1_time = now - timedelta(days=5)
        build2_time = now - timedelta(days=10)

        cached_images = [
            # Normal tags
            Image('test.ocir.io/testnamespace/myapp:v2.5.1', ocid='ocid1.image.1', created_at=build1_time, digest='sha256:tag1digest'),
            Image('test.ocir.io/testnamespace/myapp:832992d', ocid='ocid1.image.2', created_at=build1_time, digest='sha256:tag2digest'),
            Image('test.ocir.io/testnamespace/myapp:latest', ocid='ocid1.image.3', created_at=build1_time, digest='sha256:latestdigest'),
            # Platform manifests for build1 (NOT orphans - referenced by normal tags)
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.4', created_at=build1_time, digest='sha256:aaa111'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:bbb222', ocid='ocid1.image.5', created_at=build1_time, digest='sha256:bbb222'),
            # Platform manifests for build2 (ORPHANS - not referenced by any normal tag)
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ccc333', ocid='ocid1.image.6', created_at=build2_time, digest='sha256:ccc333'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ddd444', ocid='ocid1.image.7', created_at=build2_time, digest='sha256:ddd444'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # Mock manifest list resolution: normal tags reference aaa111 and bbb222
        def mock_sub_digests(image):
            if image.digest in ('sha256:tag1digest', 'sha256:tag2digest', 'sha256:latestdigest'):
                return {'sha256:aaa111', 'sha256:bbb222'}
            return set()

        with patch.object(client, '_get_manifest_list_sub_digests', side_effect=mock_sub_digests):
            images = {Image('test.ocir.io/testnamespace/myapp:v2.5.1')}
            recommendations = client.get_orphaned_manifests(images)

        assert len(recommendations) == 1
        rec = recommendations[0]
        assert rec.repository == 'testnamespace/myapp'
        assert len(rec.tags_to_delete) == 2
        orphan_ocids = {img.ocid for img in rec.tags_to_delete}
        assert 'ocid1.image.6' in orphan_ocids
        assert 'ocid1.image.7' in orphan_ocids

    @patch('src.registry_client.oci')
    def test_get_orphaned_manifests_no_orphans(self, mock_oci, config):
        """Test no orphans when all platform manifests are referenced by normal tags."""
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

        now = datetime.now(timezone.utc)
        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:v1.0.0', ocid='ocid1.image.1', created_at=now, digest='sha256:tagdigest'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.2', created_at=now, digest='sha256:aaa111'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:bbb222', ocid='ocid1.image.3', created_at=now, digest='sha256:bbb222'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        with patch.object(client, '_get_manifest_list_sub_digests', return_value={'sha256:aaa111', 'sha256:bbb222'}):
            images = {Image('test.ocir.io/testnamespace/myapp:v1.0.0')}
            recommendations = client.get_orphaned_manifests(images)

        assert len(recommendations) == 0

    @patch('src.registry_client.oci')
    def test_get_orphaned_manifests_all_orphans(self, mock_oci, config):
        """Test all platform manifests are orphans when no normal tags reference them."""
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

        old_time = datetime.now(timezone.utc) - timedelta(days=30)
        cached_images = [
            # A normal tag that doesn't reference any of the platform manifests
            Image('test.ocir.io/testnamespace/myapp:latest', ocid='ocid1.image.0', created_at=old_time, digest='sha256:latestdigest'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.1', created_at=old_time, digest='sha256:aaa111'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:bbb222', ocid='ocid1.image.2', created_at=old_time, digest='sha256:bbb222'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ccc333', ocid='ocid1.image.3', created_at=old_time + timedelta(days=1), digest='sha256:ccc333'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # latest tag references different sub-manifests (not aaa111/bbb222/ccc333)
        with patch.object(client, '_get_manifest_list_sub_digests', return_value={'sha256:other1', 'sha256:other2'}):
            images = {Image('test.ocir.io/testnamespace/myapp:latest')}
            recommendations = client.get_orphaned_manifests(images)

        assert len(recommendations) == 1
        assert len(recommendations[0].tags_to_delete) == 3

    @patch('src.registry_client.oci')
    def test_get_orphaned_manifests_latest_protected(self, mock_oci, config):
        """Test platform manifests referenced by latest's manifest list are NOT orphans."""
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

        now = datetime.now(timezone.utc)
        old_time = now - timedelta(days=30)

        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:latest', ocid='ocid1.image.1', created_at=now, digest='sha256:latestdigest'),
            # Platform manifests referenced by latest -> NOT orphans
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.2', created_at=now, digest='sha256:aaa111'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:bbb222', ocid='ocid1.image.3', created_at=now, digest='sha256:bbb222'),
            # Platform manifest NOT referenced by any tag -> orphan
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ccc333', ocid='ocid1.image.4', created_at=old_time, digest='sha256:ccc333'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # latest references aaa111 and bbb222 but not ccc333
        with patch.object(client, '_get_manifest_list_sub_digests', return_value={'sha256:aaa111', 'sha256:bbb222'}):
            images = {Image('test.ocir.io/testnamespace/myapp:latest')}
            recommendations = client.get_orphaned_manifests(images)

        assert len(recommendations) == 1
        assert len(recommendations[0].tags_to_delete) == 1
        assert recommendations[0].tags_to_delete[0].ocid == 'ocid1.image.4'

    @patch('src.registry_client.oci')
    def test_get_orphaned_manifests_deployed_image_protected(self, mock_oci, config):
        """Test platform manifests referenced by deployed image's manifest list are NOT orphans."""
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

        now = datetime.now(timezone.utc)
        deployed_time = now - timedelta(days=2)
        orphan_time = now - timedelta(days=20)

        cached_images = [
            # Currently deployed githash image
            Image('test.ocir.io/testnamespace/myapp:a1b2c3d', ocid='ocid1.image.1', created_at=deployed_time, digest='sha256:deployeddigest'),
            # Platform manifests referenced by deployed image -> NOT orphans
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.2', created_at=deployed_time, digest='sha256:aaa111'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:bbb222', ocid='ocid1.image.3', created_at=deployed_time, digest='sha256:bbb222'),
            # Orphaned platform manifests from old deleted build
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ccc333', ocid='ocid1.image.4', created_at=orphan_time, digest='sha256:ccc333'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ddd444', ocid='ocid1.image.5', created_at=orphan_time, digest='sha256:ddd444'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # Deployed image references aaa111 and bbb222
        with patch.object(client, '_get_manifest_list_sub_digests', return_value={'sha256:aaa111', 'sha256:bbb222'}):
            images = {Image('test.ocir.io/testnamespace/myapp:a1b2c3d')}
            recommendations = client.get_orphaned_manifests(images)

        assert len(recommendations) == 1
        assert len(recommendations[0].tags_to_delete) == 2
        orphan_ocids = {img.ocid for img in recommendations[0].tags_to_delete}
        assert 'ocid1.image.4' in orphan_ocids
        assert 'ocid1.image.5' in orphan_ocids

    @patch('src.registry_client.oci')
    def test_get_orphaned_manifests_skips_when_no_digests_resolved(self, mock_oci, config):
        """Test orphan detection skips repo when manifest list resolution fails entirely."""
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

        now = datetime.now(timezone.utc)
        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:v1.0.0', ocid='ocid1.image.1', created_at=now, digest='sha256:tagdigest'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.2', created_at=now, digest='sha256:aaa111'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # Simulate manifest list resolution failure (returns empty set)
        with patch.object(client, '_get_manifest_list_sub_digests', return_value=set()):
            images = {Image('test.ocir.io/testnamespace/myapp:v1.0.0')}
            recommendations = client.get_orphaned_manifests(images)

        # Should skip - not delete anything when we can't resolve manifests
        assert len(recommendations) == 0

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
    def test_delete_ocir_images_skips_already_deleted(self, mock_oci, config):
        """Test delete_ocir_images handles 404 for already-deleted images."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts_client = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts_client
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        # Second delete raises 404 (same underlying image already deleted)
        not_found_error = mock_oci.exceptions.ServiceError(
            status=404, code='REPO_ID_UNKNOWN', headers={}, message='Image Id Unknown'
        )
        mock_artifacts_client.delete_container_image.side_effect = [
            None,  # first delete succeeds
            not_found_error,  # second delete 404s
        ]

        client = RegistryClient(config)

        img1 = Image('test.ocir.io/testnamespace/myapp:old1', ocid='ocid1.image.1')
        img2 = Image('test.ocir.io/testnamespace/myapp:old2', ocid='ocid1.image.1')  # same OCID
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

    @patch('src.registry_client.oci')
    def test_delete_ocir_images_no_client(self, mock_oci, config):
        """Test delete_ocir_images returns empty when no SDK client."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = RegistryClient(config)
        recommendations = []

        result = client.delete_ocir_images(recommendations)

        assert result == {}

    @patch('src.registry_client.requests.get')
    @patch('builtins.open', new_callable=mock_open,
           read_data=json.dumps({'auths': {'iad.ocir.io': {'auth': 'dXNlcjpwYXNz'}}}))
    @patch('src.registry_client.oci')
    def test_get_docker_auth_basic_accepted(self, mock_oci, mock_file, mock_get, config):
        """Test _get_docker_auth returns Basic header when registry accepts it directly."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        # Registry accepts Basic auth directly (200)
        mock_v2_resp = Mock()
        mock_v2_resp.status_code = 200
        mock_get.return_value = mock_v2_resp

        client = RegistryClient(config)
        image = Image('iad.ocir.io/tnoff/myapp:v1.0.0')
        result = client._get_docker_auth(image)

        assert result == {'Authorization': 'Basic dXNlcjpwYXNz'}

    @patch('src.registry_client.requests.get')
    @patch('builtins.open', new_callable=mock_open,
           read_data=json.dumps({'auths': {'iad.ocir.io': {'auth': 'dXNlcjpwYXNz'}}}))
    @patch('src.registry_client.oci')
    def test_get_docker_auth_token_exchange(self, mock_oci, mock_file, mock_get, config):
        """Test _get_docker_auth does token exchange when registry requires Bearer auth."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        # Registry returns 401 with WWW-Authenticate challenge
        mock_v2_resp = Mock()
        mock_v2_resp.status_code = 401
        mock_v2_resp.headers = {
            'WWW-Authenticate': 'Bearer realm="https://iad.ocir.io/20180419/docker/token",service="iad.ocir.io",scope=""'
        }

        # Token endpoint returns a token
        mock_token_resp = Mock()
        mock_token_resp.ok = True
        mock_token_resp.json.return_value = {'token': 'my-bearer-token'}

        mock_get.side_effect = [mock_v2_resp, mock_token_resp]

        client = RegistryClient(config)
        image = Image('iad.ocir.io/tnoff/myapp:v1.0.0')
        result = client._get_docker_auth(image)

        assert result == {'Authorization': 'Bearer my-bearer-token'}
        # Verify token request included correct scope
        token_call = mock_get.call_args_list[1]
        assert token_call[1]['params']['scope'] == 'repository:tnoff/myapp:pull'

    @patch('builtins.open', side_effect=FileNotFoundError)
    @patch('src.registry_client.oci')
    def test_get_docker_auth_missing_config(self, mock_oci, mock_file, config):
        """Test _get_docker_auth returns None when config file is missing."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)
        image = Image('iad.ocir.io/tnoff/myapp:v1.0.0')
        result = client._get_docker_auth(image)

        assert result is None

    @patch('builtins.open', new_callable=mock_open,
           read_data=json.dumps({'auths': {'other.registry.io': {'auth': 'dXNlcjpwYXNz'}}}))
    @patch('src.registry_client.oci')
    def test_get_docker_auth_no_entry_for_registry(self, mock_oci, mock_file, config):
        """Test _get_docker_auth returns None when no entry for the registry."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)
        image = Image('iad.ocir.io/tnoff/myapp:v1.0.0')
        result = client._get_docker_auth(image)

        assert result is None

    @patch('src.registry_client.requests.get')
    @patch('src.registry_client.oci')
    def test_get_manifest_list_sub_digests_manifest_list(self, mock_oci, mock_get, config):
        """Test _get_manifest_list_sub_digests returns sub-digests for manifest lists."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)

        manifest_list_response = {
            'mediaType': 'application/vnd.docker.distribution.manifest.list.v2+json',
            'manifests': [
                {'digest': 'sha256:sub1', 'platform': {'architecture': 'amd64'}},
                {'digest': 'sha256:sub2', 'platform': {'architecture': 'arm64'}},
            ]
        }
        mock_resp = Mock()
        mock_resp.json.return_value = manifest_list_response
        mock_resp.raise_for_status = Mock()
        mock_get.return_value = mock_resp

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0', digest='sha256:manifest_list')
        # Mock _get_docker_auth to return auth
        client._get_docker_auth = Mock(return_value={'Authorization': 'Basic dXNlcjpwYXNz'})

        result = client._get_manifest_list_sub_digests(image)

        assert result == {'sha256:sub1', 'sha256:sub2'}

    @patch('src.registry_client.requests.get')
    @patch('src.registry_client.oci')
    def test_get_manifest_list_sub_digests_non_list(self, mock_oci, mock_get, config):
        """Test _get_manifest_list_sub_digests returns empty set for non-list manifests."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)

        single_manifest_response = {
            'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
            'config': {'digest': 'sha256:config123'},
        }
        mock_resp = Mock()
        mock_resp.json.return_value = single_manifest_response
        mock_resp.raise_for_status = Mock()
        mock_get.return_value = mock_resp

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0', digest='sha256:single')
        client._get_docker_auth = Mock(return_value={'Authorization': 'Basic dXNlcjpwYXNz'})

        result = client._get_manifest_list_sub_digests(image)

        assert result == set()

    @patch('src.registry_client.oci')
    def test_get_manifest_list_sub_digests_no_digest(self, mock_oci, config):
        """Test _get_manifest_list_sub_digests returns empty set when image has no digest."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0')
        result = client._get_manifest_list_sub_digests(image)

        assert result == set()

    @patch('src.registry_client.requests.get')
    @patch('src.registry_client.oci')
    def test_get_manifest_list_sub_digests_api_error(self, mock_oci, mock_get, config):
        """Test _get_manifest_list_sub_digests returns empty set on API error."""
        mock_oci.config.from_file.return_value = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.artifacts.ArtifactsClient.return_value = Mock()
        mock_oci.identity.IdentityClient.return_value = Mock()
        mock_oci.object_storage.ObjectStorageClient.return_value = Mock()

        client = RegistryClient(config)
        mock_get.side_effect = requests.exceptions.ConnectionError("connection refused")

        image = Image('test.ocir.io/testnamespace/myapp:v1.0.0', digest='sha256:abc')
        client._get_docker_auth = Mock(return_value={'Authorization': 'Basic dXNlcjpwYXNz'})

        result = client._get_manifest_list_sub_digests(image)

        assert result == set()

    @patch('src.registry_client.oci')
    def test_get_old_ocir_images_protects_sub_manifest_digests(self, mock_oci, config):
        """Test get_old_ocir_images protects sub-manifest digests from deletion."""
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

        now = datetime.now(timezone.utc)
        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:deployed', ocid='ocid1.image.0',
                  created_at=now, digest='sha256:deployed_digest'),
            Image('test.ocir.io/testnamespace/myapp:old1', ocid='ocid1.image.1',
                  created_at=now - timedelta(days=10), digest='sha256:sub1'),
            Image('test.ocir.io/testnamespace/myapp:old2', ocid='ocid1.image.2',
                  created_at=now - timedelta(days=9), digest='sha256:unrelated'),
            Image('test.ocir.io/testnamespace/myapp:old3', ocid='ocid1.image.3',
                  created_at=now - timedelta(days=8), digest='sha256:sub2'),
            Image('test.ocir.io/testnamespace/myapp:kept', ocid='ocid1.image.4',
                  created_at=now - timedelta(days=1), digest='sha256:kept_digest'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # Mock _get_manifest_list_sub_digests: deployed image is a manifest list
        def mock_sub_digests(image):
            if image.digest == 'sha256:deployed_digest':
                return {'sha256:sub1', 'sha256:sub2'}
            return set()
        client._get_manifest_list_sub_digests = Mock(side_effect=mock_sub_digests)

        images = [Image('test.ocir.io/testnamespace/myapp:deployed')]
        recommendations = client.get_old_ocir_images(images, keep_count=1)

        assert len(recommendations) == 1
        rec = recommendations[0]
        deleted_tags = {img.tag for img in rec.tags_to_delete}
        # old1 (sha256:sub1) and old3 (sha256:sub2) are sub-manifests and should be protected
        assert 'old1' not in deleted_tags
        assert 'old3' not in deleted_tags
        # old2 (sha256:unrelated) should still be deleted
        assert 'old2' in deleted_tags

    @patch('src.registry_client.oci')
    def test_get_old_ocir_images_no_manifest_lists_no_regression(self, mock_oci, config):
        """Test get_old_ocir_images behaves unchanged when no manifest lists exist."""
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

        now = datetime.now(timezone.utc)
        cached_images = []
        for i in range(8):
            img = Image(
                f'test.ocir.io/testnamespace/myapp:tag{i:02d}',
                ocid=f'ocid1.image.{i}',
                created_at=now - timedelta(days=i),
                digest=f'sha256:digest{i}',
            )
            cached_images.append(img)
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        # No manifest lists — _get_manifest_list_sub_digests always returns empty
        client._get_manifest_list_sub_digests = Mock(return_value=set())

        images = [Image('test.ocir.io/testnamespace/myapp:tag00')]
        recommendations = client.get_old_ocir_images(images, keep_count=3)

        assert len(recommendations) == 1
        rec = recommendations[0]
        # 8 total - 1 deployed - 3 kept = 4 to delete
        assert len(rec.tags_to_delete) == 4

    @patch('src.registry_client.oci')
    def test_get_old_ocir_images_excludes_platform_manifests(self, mock_oci, config):
        """Test get_old_ocir_images ignores platform manifests (unknown@sha256:...) entirely.

        Platform manifests should only be handled by get_orphaned_manifests().
        Previously, platform manifests were mixed into the keep_count logic, which
        could cause a kept tag's amd64 manifest to be deleted while the tag survived,
        resulting in 'no matching manifest for linux/amd64' errors on pull.
        """
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

        now = datetime.now(timezone.utc)
        cached_images = [
            Image('test.ocir.io/testnamespace/myapp:deployed', ocid='ocid1.image.0',
                  created_at=now, digest='sha256:deployed_digest'),
            Image('test.ocir.io/testnamespace/myapp:tag1', ocid='ocid1.image.1',
                  created_at=now - timedelta(days=5), digest='sha256:tag1_digest'),
            Image('test.ocir.io/testnamespace/myapp:tag2', ocid='ocid1.image.2',
                  created_at=now - timedelta(days=10), digest='sha256:tag2_digest'),
            # Platform manifests should NOT be included in keep_count or deletion
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:aaa111', ocid='ocid1.image.10',
                  created_at=now - timedelta(days=1), digest='sha256:aaa111'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:bbb222', ocid='ocid1.image.11',
                  created_at=now - timedelta(days=1), digest='sha256:bbb222'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ccc333', ocid='ocid1.image.12',
                  created_at=now - timedelta(days=5), digest='sha256:ccc333'),
            Image('test.ocir.io/testnamespace/myapp:unknown@sha256:ddd444', ocid='ocid1.image.13',
                  created_at=now - timedelta(days=5), digest='sha256:ddd444'),
        ]
        client._ocir_image_cache['testnamespace/myapp'] = cached_images

        client._get_manifest_list_sub_digests = Mock(return_value=set())

        images = [Image('test.ocir.io/testnamespace/myapp:deployed')]
        # keep_count=1 means keep deployed + 1 newest tag = tag1 kept, tag2 deleted
        recommendations = client.get_old_ocir_images(images, keep_count=1)

        assert len(recommendations) == 1
        rec = recommendations[0]
        deleted_tags = {img.tag for img in rec.tags_to_delete}
        # Only tag2 should be deleted — platform manifests must NOT appear
        assert deleted_tags == {'tag2'}
        # Verify no platform manifest was included
        for img in rec.tags_to_delete:
            assert 'unknown@sha256:' not in img.full_name

    @patch('src.registry_client.oci')
    def test_delete_ocir_images_invalidates_cache(self, mock_oci, config):
        """Test that delete_ocir_images invalidates the cache for modified repos."""
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)
        # Pre-populate cache
        client._ocir_image_cache['testnamespace/myapp'] = [Image('test.ocir.io/testnamespace/myapp:old')]
        client._ocir_image_cache['testnamespace/other'] = [Image('test.ocir.io/testnamespace/other:old')]

        image_to_delete = Image('test.ocir.io/testnamespace/myapp:old', ocid='ocid1.image.1')
        recommendation = CleanupRecommendation(
            registry='test.ocir.io',
            repository='testnamespace/myapp',
            tags_to_delete=[image_to_delete],
        )

        client.delete_ocir_images([recommendation])

        # Cache for the modified repo should be invalidated
        assert 'testnamespace/myapp' not in client._ocir_image_cache
        # Cache for other repos should remain
        assert 'testnamespace/other' in client._ocir_image_cache

    @patch('src.registry_client.oci')
    def test_old_image_cleanup_then_orphan_detection_deletes_intermediate_tags(self, mock_oci, config):
        """End-to-end: after old tags are deleted, orphan detection finds and removes
        their platform manifests while keeping platform manifests of surviving tags.

        Scenario: 7 tagged images with 2 platform manifests each (amd64 + arm64).
        keep_count=5, so the 2 oldest tags are deleted. Their 4 platform manifests
        should then be detected as orphans, while the 10 platform manifests belonging
        to the 5 kept tags + deployed remain referenced.
        """
        mock_config = {'tenancy': 'ocid1.tenancy.test'}
        mock_oci.config.from_file.return_value = mock_config

        mock_artifacts = Mock()
        mock_oci.artifacts.ArtifactsClient.return_value = mock_artifacts
        mock_oci.identity.IdentityClient.return_value = Mock()

        mock_object_client = Mock()
        mock_response = Mock()
        mock_response.data = 'testnamespace'
        mock_object_client.get_namespace.return_value = mock_response
        mock_oci.object_storage.ObjectStorageClient.return_value = mock_object_client

        client = RegistryClient(config)
        client._repository_compartment_cache['myapp'] = 'ocid1.compartment.apps'

        now = datetime.now(timezone.utc)

        # Build the full image list: 1 deployed + 7 other tags, each with 2 platform manifests
        # Tag layout (newest first):
        #   deployed (day 0)  -> plat sha256:deployed_amd64, sha256:deployed_arm64
        #   tag6 (day 1)      -> plat sha256:tag6_amd64, sha256:tag6_arm64
        #   tag5 (day 2)      -> plat sha256:tag5_amd64, sha256:tag5_arm64
        #   tag4 (day 3)      -> plat sha256:tag4_amd64, sha256:tag4_arm64
        #   tag3 (day 4)      -> plat sha256:tag3_amd64, sha256:tag3_arm64
        #   tag2 (day 5)      -> plat sha256:tag2_amd64, sha256:tag2_arm64
        #   --- keep_count=5 boundary (tag2-tag6 kept) ---
        #   tag1 (day 6)      -> plat sha256:tag1_amd64, sha256:tag1_arm64  <-- DELETE
        #   tag0 (day 7)      -> plat sha256:tag0_amd64, sha256:tag0_arm64  <-- DELETE

        all_images = []
        tag_names = ['deployed'] + [f'tag{i}' for i in range(7)]
        for idx, tag_name in enumerate(tag_names):
            day_offset = idx  # deployed=0, tag6=1, ..., tag0=7
            # Reverse so tag6 is newest non-deployed
            if tag_name != 'deployed':
                day_offset = 8 - int(tag_name.replace('tag', ''))
            else:
                day_offset = 0
            created = now - timedelta(days=day_offset)
            digest = f'sha256:{tag_name}_digest'

            all_images.append(Image(
                f'test.ocir.io/testnamespace/myapp:{tag_name}',
                ocid=f'ocid1.image.{tag_name}',
                created_at=created,
                digest=digest,
            ))
            # Two platform manifests per tag
            for arch in ['amd64', 'arm64']:
                plat_digest = f'sha256:{tag_name}_{arch}'
                all_images.append(Image(
                    f'test.ocir.io/testnamespace/myapp:unknown@{plat_digest}',
                    ocid=f'ocid1.image.{tag_name}_{arch}',
                    created_at=created,
                    digest=plat_digest,
                ))

        # Manifest list sub-digest mapping: each tag references its two platform digests
        manifest_map = {}
        for tag_name in tag_names:
            manifest_map[f'sha256:{tag_name}_digest'] = {
                f'sha256:{tag_name}_amd64', f'sha256:{tag_name}_arm64',
            }

        def mock_sub_digests(image):
            return manifest_map.get(image.digest, set())
        client._get_manifest_list_sub_digests = Mock(side_effect=mock_sub_digests)

        # --- Step 1: get_old_ocir_images ---
        client._ocir_image_cache['testnamespace/myapp'] = list(all_images)
        images = {Image('test.ocir.io/testnamespace/myapp:deployed')}
        old_recommendations = client.get_old_ocir_images(images, keep_count=5)

        assert len(old_recommendations) == 1
        old_rec = old_recommendations[0]
        old_deleted_tags = {img.tag for img in old_rec.tags_to_delete}
        # Only the 2 oldest normal tags should be marked for deletion
        assert old_deleted_tags == {'tag0', 'tag1'}
        # No platform manifests should appear
        for img in old_rec.tags_to_delete:
            assert 'unknown@sha256:' not in img.full_name

        # --- Step 2: simulate deletion + cache invalidation ---
        client.delete_ocir_images(old_recommendations)
        assert 'testnamespace/myapp' not in client._ocir_image_cache

        # --- Step 3: get_orphaned_manifests with fresh data (tags deleted) ---
        # Simulate what OCIR returns after the old tags were deleted:
        # tag0 and tag1 are gone, their platform manifests remain as orphans
        post_deletion_images = [im for im in all_images
                                if im.tag not in ('tag0', 'tag1')]
        client._ocir_image_cache['testnamespace/myapp'] = post_deletion_images

        orphan_recommendations = client.get_orphaned_manifests(
            {Image('test.ocir.io/testnamespace/myapp:deployed')},
        )

        assert len(orphan_recommendations) == 1
        orphan_rec = orphan_recommendations[0]
        orphan_digests = {img.digest for img in orphan_rec.tags_to_delete}
        # The 4 platform manifests from tag0 and tag1 should be orphans
        assert orphan_digests == {
            'sha256:tag0_amd64', 'sha256:tag0_arm64',
            'sha256:tag1_amd64', 'sha256:tag1_arm64',
        }
        # Platform manifests for kept tags must NOT be in orphans
        for kept_tag in ['deployed', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6']:
            assert f'sha256:{kept_tag}_amd64' not in orphan_digests
            assert f'sha256:{kept_tag}_arm64' not in orphan_digests
