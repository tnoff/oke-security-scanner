"""OKE client for checking node pool image updates."""

import re
from dataclasses import dataclass
from datetime import datetime
from logging import getLogger
from typing import Optional

import oci
from opentelemetry import trace

from .config import Config

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)

OTEL_PREFIX = 'oke'

# Pattern to extract date from Oracle Linux image names
# e.g., Oracle-Linux-8.10-aarch64-2025.11.20-0 -> 2025.11.20
IMAGE_DATE_PATTERN = re.compile(r'^(Oracle-Linux-[\d.]+-\w+)-(\d{4}\.\d{2}\.\d{2})-\d+$')


@dataclass
class NodePoolImageInfo:
    """Information about a node pool's current image."""
    node_pool_name: str
    node_pool_id: str
    current_image_id: str
    current_image_name: str
    current_image_date: Optional[datetime]
    kubernetes_version: str


@dataclass
class AvailableImage:
    """Information about an available node image."""
    image_id: str
    image_name: str
    image_date: Optional[datetime]


@dataclass
class NodeImageUpdateInfo:
    """Information about an available node image update."""
    node_pool_name: str
    kubernetes_version: str
    current_image_name: str
    current_image_date: Optional[datetime]
    latest_image_name: str
    latest_image_date: Optional[datetime]
    latest_image_id: str


def parse_image_date(image_name: str) -> Optional[datetime]:
    """Parse date from Oracle Linux image name.

    Args:
        image_name: Image name like 'Oracle-Linux-8.10-aarch64-2025.11.20-0'

    Returns:
        Datetime object or None if pattern doesn't match
    """
    match = IMAGE_DATE_PATTERN.match(image_name)
    if match:
        date_str = match.group(2)  # e.g., '2025.11.20'
        try:
            return datetime.strptime(date_str, '%Y.%m.%d')
        except ValueError:
            logger.warning(f"Failed to parse date from image name: {image_name}")
            return None
    return None


def get_image_base_pattern(image_name: str) -> Optional[str]:
    """Extract base pattern from image name for matching.

    Args:
        image_name: Image name like 'Oracle-Linux-8.10-aarch64-2025.11.20-0'

    Returns:
        Base pattern like 'Oracle-Linux-8.10-aarch64' or None
    """
    match = IMAGE_DATE_PATTERN.match(image_name)
    if match:
        return match.group(1)
    return None


class OKEClient:
    """Client for checking OKE node pool image updates."""

    def __init__(self, config: Config):
        """Initialize OKE client.

        Args:
            config: Application configuration
        """
        self.config = config
        self.container_engine_client = None
        self.compute_client = None
        self.oci_config = None

        try:
            self.oci_config = oci.config.from_file()
            self.container_engine_client = oci.container_engine.ContainerEngineClient(self.oci_config)
            self.compute_client = oci.core.ComputeClient(self.oci_config)
            logger.info("OKEClient initialized with OCI SDK")
        except Exception as e:
            logger.warning(f"Failed to initialize OCI SDK client: {e}")
            logger.warning("OKE node image checking will not work without OCI credentials")

    def get_node_pools(self) -> list[NodePoolImageInfo]:
        """Get all node pools and their current image information.

        Returns:
            List of NodePoolImageInfo for each node pool
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_node_pools'):
            if not self.container_engine_client:
                logger.warning("Container Engine client not available")
                return []

            if not self.config.oke_cluster_ocid:
                logger.warning("OKE_CLUSTER_OCID not configured")
                return []

            node_pools = []

            try:
                # List all node pools in the cluster
                response = self.container_engine_client.list_node_pools(
                    compartment_id=self._get_compartment_from_cluster(),
                    cluster_id=self.config.oke_cluster_ocid
                )

                for np in response.data:
                    # Get detailed node pool info
                    np_detail = self.container_engine_client.get_node_pool(np.id).data

                    # Extract image info from node_source_details
                    image_id = None
                    image_name = None
                    if np_detail.node_source_details:
                        image_id = np_detail.node_source_details.image_id
                        # Look up image name
                        if image_id and self.compute_client:
                            try:
                                image = self.compute_client.get_image(image_id).data
                                image_name = image.display_name
                            except Exception as e:
                                logger.warning(f"Failed to get image details for {image_id}: {e}")
                                image_name = image_id

                    image_date = parse_image_date(image_name) if image_name else None

                    node_pools.append(NodePoolImageInfo(
                        node_pool_name=np_detail.name,
                        node_pool_id=np_detail.id,
                        current_image_id=image_id,
                        current_image_name=image_name or "Unknown",
                        current_image_date=image_date,
                        kubernetes_version=np_detail.kubernetes_version,
                    ))

                logger.info(f"Found {len(node_pools)} node pools in cluster")
                return node_pools

            except Exception as e:
                logger.error(f"Failed to get node pools: {e}")
                return []

    def _get_compartment_from_cluster(self) -> Optional[str]:
        """Get compartment ID from cluster OCID."""
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_compartment'):
            if not self.container_engine_client or not self.config.oke_cluster_ocid:
                return None

            try:
                cluster = self.container_engine_client.get_cluster(self.config.oke_cluster_ocid).data
                return cluster.compartment_id
            except Exception as e:
                logger.error(f"Failed to get cluster details: {e}")
                return None

    def get_available_images(self, compartment_id: str, os_type: str = "Oracle Linux",
                             os_arch: str = None) -> list[AvailableImage]:
        """Get available node images from Container Engine API.

        Args:
            compartment_id: Compartment to search in
            os_type: OS type filter (default: "Oracle Linux")
            os_arch: OS architecture filter (e.g., "aarch64")

        Returns:
            List of available images
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_available_images'):
            if not self.container_engine_client:
                return []

            try:
                # Use get_node_pool_options to list available images
                kwargs = {
                    'node_pool_option_id': self.config.oke_cluster_ocid,
                    'compartment_id': compartment_id,
                    'node_pool_os': os_type,
                }
                if os_arch:
                    kwargs['node_pool_os_arch'] = os_arch

                response = self.container_engine_client.get_node_pool_options(**kwargs)

                available = []
                for source in response.data.sources:
                    if source.source_type == "IMAGE":
                        image_date = parse_image_date(source.source_name)
                        available.append(AvailableImage(
                            image_id=source.image_id,
                            image_name=source.source_name,
                            image_date=image_date,
                        ))

                logger.debug(f"Found {len(available)} available images")
                return available

            except Exception as e:
                logger.error(f"Failed to get available images: {e}")
                return []

    def check_for_updates(self) -> list[NodeImageUpdateInfo]:
        """Check if any node pools have newer images available.

        Returns:
            List of NodeImageUpdateInfo for pools with updates available
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.check_for_updates'):
            updates = []

            # Get current node pools
            node_pools = self.get_node_pools()
            if not node_pools:
                logger.info("No node pools found or unable to query")
                return []

            # Get compartment for image lookup
            compartment_id = self._get_compartment_from_cluster()
            if not compartment_id:
                logger.warning("Could not determine compartment ID")
                return []

            # Get all available images
            available_images = self.get_available_images(compartment_id)
            if not available_images:
                logger.warning("No available images found")
                return []

            # Check each node pool
            for np in node_pools:
                logger.info(f"Checking node pool {np.node_pool_name} for updates")

                # Get base pattern from current image
                base_pattern = get_image_base_pattern(np.current_image_name)
                if not base_pattern:
                    logger.warning(f"Could not parse image pattern from {np.current_image_name}")
                    continue

                # Find matching images with newer dates
                matching_images = [
                    img for img in available_images
                    if img.image_name.startswith(base_pattern) and img.image_date
                ]

                if not matching_images:
                    logger.debug(f"No matching images found for pattern {base_pattern}")
                    continue

                # Sort by date and get the newest
                matching_images.sort(key=lambda x: x.image_date, reverse=True)
                newest = matching_images[0]

                # Compare with current
                if np.current_image_date and newest.image_date > np.current_image_date:
                    logger.info(
                        f"Node pool {np.node_pool_name} has update available: "
                        f"{np.current_image_name} -> {newest.image_name}"
                    )
                    updates.append(NodeImageUpdateInfo(
                        node_pool_name=np.node_pool_name,
                        kubernetes_version=np.kubernetes_version,
                        current_image_name=np.current_image_name,
                        current_image_date=np.current_image_date,
                        latest_image_name=newest.image_name,
                        latest_image_date=newest.image_date,
                        latest_image_id=newest.image_id,
                    ))
                else:
                    logger.info(f"Node pool {np.node_pool_name} is up to date")

            return updates
