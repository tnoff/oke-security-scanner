"""Tests for oke_client module."""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.oke_client import (
    parse_image_date,
    get_image_base_pattern,
    OKEClient,
    NodePoolImageInfo,
    AvailableImage,
    NodeImageUpdateInfo,
)


class TestParseImageDate:
    """Tests for parse_image_date function."""

    def test_valid_oracle_linux_image(self):
        """Test parsing date from a standard Oracle Linux image name."""
        result = parse_image_date("Oracle-Linux-8.10-aarch64-2025.11.20-0")
        assert result == datetime(2025, 11, 20)

    def test_valid_oracle_linux_x86(self):
        """Test parsing date from an x86_64 image name."""
        result = parse_image_date("Oracle-Linux-8.10-x86_64-2025.12.01-0")
        assert result == datetime(2025, 12, 1)

    def test_different_version(self):
        """Test parsing date from a different OS version."""
        result = parse_image_date("Oracle-Linux-9.3-aarch64-2024.06.15-0")
        assert result == datetime(2024, 6, 15)

    def test_non_matching_name(self):
        """Test that non-matching image names return None."""
        result = parse_image_date("custom-image-v1.0")
        assert result is None

    def test_empty_string(self):
        """Test empty string returns None."""
        result = parse_image_date("")
        assert result is None

    def test_partial_match(self):
        """Test that partial matches don't parse."""
        result = parse_image_date("Oracle-Linux-8.10-aarch64")
        assert result is None


class TestGetImageBasePattern:
    """Tests for get_image_base_pattern function."""

    def test_valid_image_name(self):
        """Test extracting base pattern from a valid image name."""
        result = get_image_base_pattern("Oracle-Linux-8.10-aarch64-2025.11.20-0")
        assert result == "Oracle-Linux-8.10-aarch64"

    def test_different_arch(self):
        """Test extracting base pattern with different architecture."""
        result = get_image_base_pattern("Oracle-Linux-8.10-x86_64-2025.12.01-0")
        assert result == "Oracle-Linux-8.10-x86_64"

    def test_non_matching_name(self):
        """Test that non-matching image names return None."""
        result = get_image_base_pattern("custom-image-v1.0")
        assert result is None

    def test_empty_string(self):
        """Test empty string returns None."""
        result = get_image_base_pattern("")
        assert result is None


class TestOKEClient:
    """Tests for OKEClient class."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock config for OKE client."""
        config = Mock()
        config.oke_cluster_ocid = "ocid1.cluster.oc1.test"
        config.oke_image_check_enabled = True
        return config

    @patch('src.oke_client.oci')
    def test_init_success(self, mock_oci, mock_config):
        """Test successful OKE client initialization."""
        mock_oci.config.from_file.return_value = {"region": "us-ashburn-1"}

        client = OKEClient(mock_config)

        assert client.container_engine_client is not None
        assert client.compute_client is not None

    @patch('src.oke_client.oci')
    def test_init_failure(self, mock_oci, mock_config):
        """Test OKE client initialization when OCI SDK fails."""
        mock_oci.config.from_file.side_effect = Exception("No config file")

        client = OKEClient(mock_config)

        assert client.container_engine_client is None
        assert client.compute_client is None

    @patch('src.oke_client.oci')
    def test_get_node_pools_no_client(self, mock_oci, mock_config):
        """Test get_node_pools when client is not available."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = OKEClient(mock_config)
        result = client.get_node_pools()

        assert result == []

    @patch('src.oke_client.oci')
    def test_get_node_pools_no_cluster_ocid(self, mock_oci):
        """Test get_node_pools when cluster OCID is not set."""
        config = Mock()
        config.oke_cluster_ocid = ""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(config)
        result = client.get_node_pools()

        assert result == []

    @patch('src.oke_client.oci')
    def test_get_node_pools_success(self, mock_oci, mock_config):
        """Test successful node pool retrieval."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        # Mock cluster response for compartment lookup
        mock_cluster = Mock()
        mock_cluster.compartment_id = "ocid1.compartment.oc1.test"
        client.container_engine_client.get_cluster.return_value = Mock(data=mock_cluster)

        # Mock node pool list
        mock_np_summary = Mock()
        mock_np_summary.id = "ocid1.nodepool.oc1.test"

        client.container_engine_client.list_node_pools.return_value = Mock(data=[mock_np_summary])

        # Mock node pool detail
        mock_np_detail = Mock()
        mock_np_detail.name = "pool-1"
        mock_np_detail.id = "ocid1.nodepool.oc1.test"
        mock_np_detail.kubernetes_version = "v1.28.2"
        mock_np_detail.node_source_details = Mock()
        mock_np_detail.node_source_details.image_id = "ocid1.image.oc1.test"

        client.container_engine_client.get_node_pool.return_value = Mock(data=mock_np_detail)

        # Mock image lookup
        mock_image = Mock()
        mock_image.display_name = "Oracle-Linux-8.10-aarch64-2025.11.20-0"
        client.compute_client.get_image.return_value = Mock(data=mock_image)

        result = client.get_node_pools()

        assert len(result) == 1
        assert result[0].node_pool_name == "pool-1"
        assert result[0].current_image_name == "Oracle-Linux-8.10-aarch64-2025.11.20-0"
        assert result[0].current_image_date == datetime(2025, 11, 20)
        assert result[0].kubernetes_version == "v1.28.2"

    @patch('src.oke_client.oci')
    def test_get_node_pools_exception(self, mock_oci, mock_config):
        """Test get_node_pools handles exceptions gracefully."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        # Mock compartment lookup
        mock_cluster = Mock()
        mock_cluster.compartment_id = "ocid1.compartment.oc1.test"
        client.container_engine_client.get_cluster.return_value = Mock(data=mock_cluster)

        # Make list_node_pools raise
        client.container_engine_client.list_node_pools.side_effect = Exception("API error")

        result = client.get_node_pools()
        assert result == []

    @patch('src.oke_client.oci')
    def test_get_compartment_from_cluster(self, mock_oci, mock_config):
        """Test getting compartment ID from cluster."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        mock_cluster = Mock()
        mock_cluster.compartment_id = "ocid1.compartment.oc1.test"
        client.container_engine_client.get_cluster.return_value = Mock(data=mock_cluster)

        result = client._get_compartment_from_cluster()
        assert result == "ocid1.compartment.oc1.test"

    @patch('src.oke_client.oci')
    def test_get_compartment_from_cluster_failure(self, mock_oci, mock_config):
        """Test getting compartment when API call fails."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)
        client.container_engine_client.get_cluster.side_effect = Exception("API error")

        result = client._get_compartment_from_cluster()
        assert result is None

    @patch('src.oke_client.oci')
    def test_get_available_images_no_client(self, mock_oci, mock_config):
        """Test get_available_images when client is not available."""
        mock_oci.config.from_file.side_effect = Exception("No config")

        client = OKEClient(mock_config)
        result = client.get_available_images("ocid1.compartment.oc1.test")

        assert result == []

    @patch('src.oke_client.oci')
    def test_get_available_images_success(self, mock_oci, mock_config):
        """Test successful available images retrieval."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        mock_source = Mock()
        mock_source.source_type = "IMAGE"
        mock_source.image_id = "ocid1.image.oc1.new"
        mock_source.source_name = "Oracle-Linux-8.10-aarch64-2025.12.15-0"

        mock_response = Mock()
        mock_response.data.sources = [mock_source]
        client.container_engine_client.get_node_pool_options.return_value = mock_response

        result = client.get_available_images("ocid1.compartment.oc1.test")

        assert len(result) == 1
        assert result[0].image_name == "Oracle-Linux-8.10-aarch64-2025.12.15-0"
        assert result[0].image_date == datetime(2025, 12, 15)

    @patch('src.oke_client.oci')
    def test_get_available_images_filters_non_image_sources(self, mock_oci, mock_config):
        """Test that non-IMAGE source types are filtered out."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        mock_source_image = Mock()
        mock_source_image.source_type = "IMAGE"
        mock_source_image.image_id = "ocid1.image.oc1.test"
        mock_source_image.source_name = "Oracle-Linux-8.10-aarch64-2025.12.15-0"

        mock_source_other = Mock()
        mock_source_other.source_type = "BOOT_VOLUME"

        mock_response = Mock()
        mock_response.data.sources = [mock_source_image, mock_source_other]
        client.container_engine_client.get_node_pool_options.return_value = mock_response

        result = client.get_available_images("ocid1.compartment.oc1.test")

        assert len(result) == 1

    @patch('src.oke_client.oci')
    def test_check_for_updates_with_update_available(self, mock_oci, mock_config):
        """Test check_for_updates when a newer image is available."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        # Mock get_node_pools
        client.get_node_pools = Mock(return_value=[
            NodePoolImageInfo(
                node_pool_name="pool-1",
                node_pool_id="ocid1.nodepool.oc1.test",
                current_image_id="ocid1.image.oc1.old",
                current_image_name="Oracle-Linux-8.10-aarch64-2025.11.20-0",
                current_image_date=datetime(2025, 11, 20),
                kubernetes_version="v1.28.2",
            )
        ])

        # Mock _get_compartment_from_cluster
        client._get_compartment_from_cluster = Mock(return_value="ocid1.compartment.oc1.test")

        # Mock get_available_images
        client.get_available_images = Mock(return_value=[
            AvailableImage(
                image_id="ocid1.image.oc1.new",
                image_name="Oracle-Linux-8.10-aarch64-2025.12.15-0",
                image_date=datetime(2025, 12, 15),
            ),
            AvailableImage(
                image_id="ocid1.image.oc1.old",
                image_name="Oracle-Linux-8.10-aarch64-2025.11.20-0",
                image_date=datetime(2025, 11, 20),
            ),
        ])

        result = client.check_for_updates()

        assert len(result) == 1
        assert result[0].node_pool_name == "pool-1"
        assert result[0].current_image_date == datetime(2025, 11, 20)
        assert result[0].latest_image_date == datetime(2025, 12, 15)
        assert result[0].latest_image_id == "ocid1.image.oc1.new"

    @patch('src.oke_client.oci')
    def test_check_for_updates_already_up_to_date(self, mock_oci, mock_config):
        """Test check_for_updates when node pool is already up to date."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)

        client.get_node_pools = Mock(return_value=[
            NodePoolImageInfo(
                node_pool_name="pool-1",
                node_pool_id="ocid1.nodepool.oc1.test",
                current_image_id="ocid1.image.oc1.latest",
                current_image_name="Oracle-Linux-8.10-aarch64-2025.12.15-0",
                current_image_date=datetime(2025, 12, 15),
                kubernetes_version="v1.28.2",
            )
        ])

        client._get_compartment_from_cluster = Mock(return_value="ocid1.compartment.oc1.test")

        client.get_available_images = Mock(return_value=[
            AvailableImage(
                image_id="ocid1.image.oc1.latest",
                image_name="Oracle-Linux-8.10-aarch64-2025.12.15-0",
                image_date=datetime(2025, 12, 15),
            ),
        ])

        result = client.check_for_updates()

        assert len(result) == 0

    @patch('src.oke_client.oci')
    def test_check_for_updates_no_node_pools(self, mock_oci, mock_config):
        """Test check_for_updates when there are no node pools."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)
        client.get_node_pools = Mock(return_value=[])

        result = client.check_for_updates()

        assert result == []

    @patch('src.oke_client.oci')
    def test_check_for_updates_no_compartment(self, mock_oci, mock_config):
        """Test check_for_updates when compartment cannot be determined."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)
        client.get_node_pools = Mock(return_value=[
            NodePoolImageInfo(
                node_pool_name="pool-1",
                node_pool_id="ocid1.nodepool.oc1.test",
                current_image_id="ocid1.image.oc1.old",
                current_image_name="Oracle-Linux-8.10-aarch64-2025.11.20-0",
                current_image_date=datetime(2025, 11, 20),
                kubernetes_version="v1.28.2",
            )
        ])
        client._get_compartment_from_cluster = Mock(return_value=None)

        result = client.check_for_updates()

        assert result == []

    @patch('src.oke_client.oci')
    def test_check_for_updates_no_available_images(self, mock_oci, mock_config):
        """Test check_for_updates when no available images are found."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)
        client.get_node_pools = Mock(return_value=[
            NodePoolImageInfo(
                node_pool_name="pool-1",
                node_pool_id="ocid1.nodepool.oc1.test",
                current_image_id="ocid1.image.oc1.old",
                current_image_name="Oracle-Linux-8.10-aarch64-2025.11.20-0",
                current_image_date=datetime(2025, 11, 20),
                kubernetes_version="v1.28.2",
            )
        ])
        client._get_compartment_from_cluster = Mock(return_value="ocid1.compartment.oc1.test")
        client.get_available_images = Mock(return_value=[])

        result = client.check_for_updates()

        assert result == []

    @patch('src.oke_client.oci')
    def test_check_for_updates_unrecognized_image_name(self, mock_oci, mock_config):
        """Test check_for_updates skips node pools with unrecognized image names."""
        mock_oci.config.from_file.return_value = {}

        client = OKEClient(mock_config)
        client.get_node_pools = Mock(return_value=[
            NodePoolImageInfo(
                node_pool_name="pool-1",
                node_pool_id="ocid1.nodepool.oc1.test",
                current_image_id="ocid1.image.oc1.custom",
                current_image_name="custom-image-v1.0",
                current_image_date=None,
                kubernetes_version="v1.28.2",
            )
        ])
        client._get_compartment_from_cluster = Mock(return_value="ocid1.compartment.oc1.test")
        client.get_available_images = Mock(return_value=[
            AvailableImage(
                image_id="ocid1.image.oc1.new",
                image_name="Oracle-Linux-8.10-aarch64-2025.12.15-0",
                image_date=datetime(2025, 12, 15),
            ),
        ])

        result = client.check_for_updates()

        assert result == []
