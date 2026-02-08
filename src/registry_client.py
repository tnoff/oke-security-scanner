"""OCIR registry client for fetching available image tags."""

from logging import getLogger
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

import requests
from opentelemetry import trace
import oci
from oci.regions import REGIONS_SHORT_NAMES

from .config import Config
from .k8s_client import Image, ImageVersion

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)

OTEL_PREFIX = 'registry'

@dataclass
class UpdateInfo:
    """Information about an available image update."""
    registry: str
    repo_name: str
    current: ImageVersion
    latest: ImageVersion
    is_major_update: bool = field(init=False)

    def __post_init__(self):
        self.is_major_update = False
        if self.current.is_semver and self.latest.is_semver:
            self.is_major_update = self.current.major == self.latest.major

@dataclass
class CleanupRecommendation:
    """Cleanup recommendation for an OCIR repository."""

    registry: str
    repository: str
    tags_to_delete: list[Image]

class RegistryClient:
    """Client for interacting with container registry APIs."""

    def __init__(self, cfg: Config):
        """Initialize registry client."""
        self.cfg = cfg

        # Cache for OCIR image data (repository -> list of image dicts)
        self._ocir_image_cache = {}

        # Cache for repository -> compartment_id mapping
        self._repository_compartment_cache = {}

        # OCI namespace (fetched from Object Storage API)
        self._oci_namespace: Optional[str] = None

        # OCI registry (derived from OCI config region)
        self._oci_registry: Optional[str] = None

        # Initialize OCI clients with config file authentication
        self.artifacts_client = None
        self.identity_client = None
        self.object_client = None
        self.oci_config = None
        try:
            # Try to load OCI config from default location (~/.oci/config)
            self.oci_config = oci.config.from_file()
            self.artifacts_client = oci.artifacts.ArtifactsClient(self.oci_config)
            self.identity_client = oci.identity.IdentityClient(self.oci_config)
            self.object_client = oci.object_storage.ObjectStorageClient(self.oci_config)
            logger.info(f"RegistryClient initialized with OCI SDK for OCIR: {self.oci_registry}")
        except Exception as e:
            logger.warning(f"Failed to initialize OCI SDK client: {e}")
            logger.warning("OCIR image version checking will not work without OCI credentials")

        logger.info(f"RegistryClient initialized for registry: {self.oci_registry}")

    @property
    def oci_namespace(self) -> Optional[str]:
        """Get OCI namespace from Object Storage API.

        The namespace is cached after the first retrieval.

        Returns:
            OCI namespace string, or None if unavailable
        """
        if self._oci_namespace is not None:
            return self._oci_namespace

        if not self.object_client:
            logger.warning("Object Storage client not available, cannot fetch OCI namespace")
            return None

        try:
            self._oci_namespace = self.object_client.get_namespace().data
            logger.debug(f"Retrieved OCI namespace: {self._oci_namespace}")
            return self._oci_namespace
        except Exception as e:
            logger.warning(f"Failed to get OCI namespace from Object Storage API: {e}")
            return None

    @property
    def oci_registry(self) -> Optional[str]:
        """Get OCI registry URL from OCI config region.

        Derives the OCIR URL from the region in the OCI config.
        Format: <region-key>.ocir.io

        The registry is cached after the first retrieval.

        Returns:
            OCIR registry URL (e.g., 'iad.ocir.io'), or None if unavailable
        """
        if self._oci_registry is not None:
            return self._oci_registry

        if not self.oci_config:
            logger.warning("OCI config not available, cannot derive registry URL")
            return None

        try:
            region = self.oci_config.get('region')
            if not region:
                logger.warning("No region found in OCI config")
                return None

            # Find the region key by looking up the region identifier
            region_key = None
            for key, identifier in REGIONS_SHORT_NAMES.items():
                if identifier == region:
                    region_key = key
                    break

            if region_key:
                self._oci_registry = f"{region_key}.ocir.io"
                logger.debug(f"Derived OCI registry from region {region}: {self._oci_registry}")
                return self._oci_registry

            logger.warning(f"Could not find region key for region: {region}")
            return None
        except Exception as e:
            logger.warning(f"Failed to derive OCI registry from config: {e}")
            return None

    def _strip_namespace_prefix(self, repository: str) -> str:
        """Strip namespace prefix from OCIR repository name.

        OCIR image references include the namespace in the path (e.g., 'namespace/discord_bot'),
        but the OCI API expects just the repository name without the namespace prefix.

        Args:
            repository: Full repository path (e.g., 'namespace/discord_bot')

        Returns:
            Repository name without namespace prefix (e.g., 'discord_bot')
        """
        if not self.oci_namespace:
            # Fallback: just take the last part after splitting on '/'
            if '/' in repository:
                return repository.split('/')[-1]
            return repository

        namespace_prefix = f"{self.oci_namespace}/"
        if repository.startswith(namespace_prefix):
            normalized = repository[len(namespace_prefix):]
            logger.debug(f"Stripped namespace from repository: {repository} -> {normalized}")
            return normalized

        return repository


    def _get_tenancy_id(self) -> Optional[str]:
        """Get tenancy OCID from OCI config."""
        if not self.oci_config:
            return None
        return self.oci_config.get('tenancy')

    def _list_all_compartments(self) -> list[str]:
        """List all compartments in the tenancy (including tenancy root).

        Returns:
            List of compartment OCIDs to search
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_compartments'):
            if not self.identity_client:
                return []

            tenancy_id = self._get_tenancy_id()
            if not tenancy_id:
                return []

            compartment_ids = [tenancy_id]  # Start with root tenancy

            # List all compartments in the tenancy
            response = self.identity_client.list_compartments(
                compartment_id=tenancy_id,
                compartment_id_in_subtree=True,  # Include nested compartments
                access_level="ACCESSIBLE"  # Only compartments we can access
            )

            for compartment in response.data:
                if compartment.lifecycle_state == "ACTIVE":
                    compartment_ids.append(compartment.id)

            logger.debug(f"Found {len(compartment_ids)} accessible compartments")
            return compartment_ids


    def _find_repository_compartment(self, repository: str) -> Optional[str]:
        """Find which compartment contains the given repository.

        Args:
            repository: Repository name (e.g., 'discord-bot')

        Returns:
            Compartment OCID where repository exists, or None if not found
        """
        # Make sure we take the namespace prefix out of the repo name
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.find_repo_compartment'):
            if repository in self._repository_compartment_cache:
                logger.debug(f"Using cached compartment for repository {repository}")
                return self._repository_compartment_cache[repository]

            if not self.artifacts_client:
                return None

            # Get all accessible compartments
            compartments = self._list_all_compartments()

            # Search each compartment for the repository
            for compartment_id in compartments:
                try:
                    response = self.artifacts_client.list_container_images(
                        compartment_id=compartment_id,
                        repository_name=repository,
                        limit=1  # Just check if it exists
                    )

                    # If we got any results, this compartment has the repository
                    if response.data.items:
                        logger.info(f"Found repository {repository} in compartment {compartment_id}")
                        # Cache the result
                        self._repository_compartment_cache[repository] = compartment_id
                        return compartment_id

                except oci.exceptions.ServiceError as e:
                    # 404 means repository doesn't exist in this compartment, continue searching
                    if e.status == 404:
                        continue
                    # Other errors - log and continue
                    logger.debug(f"Error checking compartment {compartment_id}: {e.message}")
                    continue

            logger.warning(f"Repository {repository} not found in any accessible compartment")
            return None

    def _get_ocir_images_via_sdk(self, image: Image) -> list[Image]:
        """Get OCIR images using OCI SDK.

        Searches across all accessible compartments to find the repository.

        Args:
            repository: Repository name (e.g., 'discord-bot', with or without namespace)

        Returns:
            List of image dictionaries with version and created_at
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_ocir_images'):
            # Check cache first (use normalized name)
            if image.repo_name in self._ocir_image_cache:
                logger.debug(f"Using cached OCIR image data for {image.repo_name}")
                return self._ocir_image_cache[image.repo_name]

            if not self.artifacts_client:
                logger.debug("OCI SDK client not available")
                return []

            # Strip namespace prefix from repository name for OCI API calls
            repository = self._strip_namespace_prefix(image.repo_name)

            # Find which compartment contains this repository
            compartment_id = self._find_repository_compartment(repository)
            if not compartment_id:
                logger.warning(f"Could not find compartment for repository {image.repo_name}")
                return []
            # List all container images in the repository
            response = self.artifacts_client.list_container_images(
                compartment_id=compartment_id,
                repository_name=repository,
            )

            images = []
            for item in response.data.items:
                # Each item has version (tag) and time_created
                if item.version and item.version != 'latest':
                    new_image = Image(f'{image.registry}/{image.repo_name}:{item.version}',
                                    ocid=item.id,
                                    created_at=item.time_created)
                    images.append(new_image)

            # Cache the results
            self._ocir_image_cache[image.repo_name] = images
            logger.debug(f"Found {len(images)} OCIR images for {image.repo_name}")
            return images

    def get_image_creation_date(self, image: Image) -> Optional[datetime]:
        """Get image creation date from manifest.

        Args:
            registry: Registry hostname
            repository: Image repository
            tag: Image tag

        Returns:
            Creation datetime or None
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_image_creation_date'):
            if image.is_ocir_image:
                images = self._get_ocir_images_via_sdk(image)
                for img in images:
                    if img.tag == image.tag and img.created_at:
                        logger.debug(f"Using cached creation date for OCIR image {image.repo_name}:{image.tag}")
                        return img.created_at
                logger.debug(f"No cached creation date found for OCIR image {image.repo_name}:{image.tag}")
                return None
            return None

    def get_image_versions(self, image: Image) -> list[Image]:
        """Fetch all tags for a given image repository.

        Args:
            registry: Registry hostname
            repository: Image repository (e.g., 'namespace/discord-bot')

        Returns:
            List of tag names
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_image_versions'):
            # Build URL and headers based on registry type
            if image.is_ocir_image:
                # Use OCI SDK for OCIR
                images = self._get_ocir_images_via_sdk(image)
                if images:
                    return images
                logger.warning(f"No images found for OCIR repository: {image.repo_name}")
                return []

            if image.registry == "docker.io":
                # Docker Hub API v2
                url = f"https://hub.docker.com/v2/repositories/{image.repo_name}/tags?page_size=200"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()
                tags = [result["name"] for result in data.get("results", []) if result != 'latest']
                return [Image(f'{image.repo_name}:{tag}') for tag in tags]

            url = f"https://{image.registry}/v2/{image.repo_name}/tags/list"
            headers = {}
            logger.debug(f"Fetching tags for {image.repo_name} from {image.registry}")
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            data = response.json()
            tags = data.get("tags", [])
            return [Image(f'{image.registry}/{image.repo_name}:{tag}') for tag in tags if tag != 'latest']


    def get_latest_version(self, image_versions: list[Image]) -> Image:
        """Get the latest version from a list of tags"""
        # Assume Image class will sort correctly
        image_versions.sort(key=lambda image: image)
        return image_versions[-1]

    def filter_non_semvers(self, image_list: list[Image]) -> list[Image]:
        '''Filter non semver images from result'''
        result = []
        for image in image_list:
            if not image.version.is_semver:
                continue
            result.append(image)
        return result

    def check_image_updates(self, images: list[Image]) -> list[UpdateInfo]:
        '''
        Check for newer versions of image

        image: K8s Client Image object
        '''
        update_info_list = []
        repo_names_processed = []
        for image in images:
            # Make sure we dont check any dupes
            if f'{image.registry}/{image.repo_name}' in repo_names_processed:
                continue
            repo_names_processed.append(f'{image.registry}/{image.repo_name}')
            with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_image_update') as span:
                logger.info(f'Checking for updates on image {image.full_name}')
                span.set_attribute('image', image.full_name)
                if image.tag == 'latest':
                    logger.debug(f"Skipping version check for {image} (latest tag)")
                    continue
                if image.is_ocir_image and image.version.is_githash and not image.created_at:
                    image.created_at = self.get_image_creation_date(image)
                available_tags = self.get_image_versions(image)

                # Filter non server images when original is a semver
                if image.version.is_semver:
                    available_tags = self.filter_non_semvers(available_tags)
                if not available_tags:
                    logger.warning(f'Unable to find new tags for image {image.full_name}')
                    continue
                newest_version = self.get_latest_version(available_tags)
                if image.version != newest_version.version:
                    if image.version.is_semver and not image.version < newest_version.version:
                        continue
                    logger.info(f'Existing image {image.full_name} has newever version available {newest_version.full_name}')
                    update_info_list.append(UpdateInfo(image.registry, image.repo_name, image.version, newest_version.version))
        return update_info_list

    def get_old_ocir_images(self, images: list[Image], keep_count: int = 5,
                       extra_repositories: list[str] = None) -> list[CleanupRecommendation]:
        '''Return report of images that can be deleted'''
        repo_names_processed = []
        extra_repositories = extra_repositories or []
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_old_ocir_images'):
            recommendations = []
            for extra_repo in extra_repositories:
                logger.info(f'Scanning extra repo {extra_repo} in old image scan')
                images.add(Image(f'{self.oci_registry}/{extra_repo}:latest'))
            for image in images:
                if f'{image.registry}/{image.repo_name}' in repo_names_processed:
                    continue
                logger.info(f'Scanning for versions of {image} that can be deleted')
                if not image.is_ocir_image:
                    continue
                all_images = self._get_ocir_images_via_sdk(image)
                # Skip the 'latest' tag and the currently deployed image
                filtered_images = [im for im in all_images if im.tag != 'latest' and im.full_name != image.full_name]
                # Then sort so we can check against the keep count
                filtered_images.sort(key=lambda im: im.created_at)
                if len(filtered_images) <= keep_count:
                    continue
                filtered_images = filtered_images[0:len(filtered_images) - keep_count]
                recommendations.append(CleanupRecommendation(image.registry, image.repo_name, filtered_images))
                repo_names_processed.append(f'{image.registry}/{image.repo_name}')

            return recommendations

    def delete_ocir_images(self, cleanup_recommendations: list[CleanupRecommendation]) -> list[Image]:
        """Delete old OCIR images based on cleanup recommendations.

        Args:
            cleanup_recommendations: Dictionary of CleanupRecommendation from get_cleanup_recommendations()

        Returns:
            Dictionary mapping repository names to DeletionResult dataclasses
        """
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.delete_old_images'):
            if not self.artifacts_client:
                logger.warning("OCI SDK not available, cannot delete OCIR images")
                return {}

            images_deleted = []

            for item in cleanup_recommendations:
                for image in item.tags_to_delete:
                    try:
                        self.artifacts_client.delete_container_image(image.ocid)
                    except oci.exceptions.ServiceError as e:
                        if e.status == 404:
                            logger.debug(f'Image {image.ocid} already deleted, skipping')
                        else:
                            raise
                    images_deleted.append(image)
            return images_deleted
