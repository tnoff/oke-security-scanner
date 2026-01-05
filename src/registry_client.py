"""OCIR registry client for fetching available image tags."""

import re
from logging import getLogger
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone

import requests
from opentelemetry import trace
import oci

from .config import Config

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)


@dataclass
class ImageVersion:
    """Represents a parsed image version."""

    tag: str
    major: Optional[int] = None
    minor: Optional[int] = None
    patch: Optional[int] = None
    is_semver: bool = False
    created_at: Optional[datetime] = None

    def __lt__(self, other: 'ImageVersion') -> bool:
        """Compare versions for sorting."""
        if self.is_semver and other.is_semver:
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        if self.created_at and other.created_at:
            return self.created_at < other.created_at
        return self.tag < other.tag

    def __eq__(self, other: 'ImageVersion') -> bool:
        """Check version equality."""
        if self.is_semver and other.is_semver:
            return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)
        return self.tag == other.tag

    def to_string(self) -> str:
        """Convert version to string representation."""
        if self.is_semver:
            return f"{self.major}.{self.minor}.{self.patch}"
        return self.tag

    def age_days(self) -> Optional[int]:
        """Calculate age in days from creation date."""
        if self.created_at:
            # Use timezone-aware datetime for comparison
            now = datetime.now(timezone.utc)
            return (now - self.created_at).days
        return None


class RegistryClient:
    """Client for interacting with container registry APIs."""

    # Semver regex pattern (supports v1.2.3 or 1.2.3 format)
    SEMVER_PATTERN = re.compile(r'^v?(\d+)\.(\d+)\.(\d+).*$')

    def __init__(self, cfg: Config):
        """Initialize registry client."""
        self.cfg = cfg
        self.oci_registry = cfg.oci_registry
        self.oci_namespace = cfg.oci_namespace

        # Cache for OCIR image data (repository -> list of image dicts)
        self._ocir_image_cache = {}

        # Cache for repository -> compartment_id mapping
        self._repository_compartment_cache = {}

        # Initialize OCI clients with config file authentication
        self.artifacts_client = None
        self.identity_client = None
        self.oci_config = None
        try:
            # Try to load OCI config from default location (~/.oci/config)
            self.oci_config = oci.config.from_file()
            self.artifacts_client = oci.artifacts.ArtifactsClient(self.oci_config)
            self.identity_client = oci.identity.IdentityClient(self.oci_config)
            logger.info(f"RegistryClient initialized with OCI SDK for OCIR: {self.oci_registry}")
        except Exception as e:
            logger.warning(f"Failed to initialize OCI SDK client: {e}")
            logger.warning("OCIR image version checking will not work without OCI credentials")

        logger.info(f"RegistryClient initialized for registry: {self.oci_registry}")

    @staticmethod
    def parse_image_name(image: str) -> Tuple[str, str, str]:
        """Parse image name into registry, repository, and tag.

        Args:
            image: Full image name (e.g., 'iad.ocir.io/namespace/discord-bot:abc123')

        Returns:
            Tuple of (registry, repository, tag)
        """
        # Split image and tag
        if ':' in image:
            image_path, tag = image.rsplit(':', 1)
        else:
            image_path, tag = image, 'latest'

        # Split registry and repository
        parts = image_path.split('/', 1)
        if len(parts) == 2 and ('.' in parts[0] or parts[0] == 'localhost'):
            # Has explicit registry (e.g., 'iad.ocir.io/namespace/discord-bot')
            registry, repository = parts
        else:
            # No explicit registry, assume Docker Hub
            registry = 'docker.io'
            repository = image_path

        return registry, repository, tag

    def is_ocir_image(self, registry: str) -> bool:
        """Check if registry is OCIR."""
        return registry == self.oci_registry

    def normalize_ocir_repository(self, repository: str) -> str:
        """Strip namespace prefix from OCIR repository name.

        OCIR image references include the namespace in the path (e.g., 'namespace/discord_bot'),
        but the OCI API expects just the repository name without the namespace prefix.

        Args:
            repository: Full repository path (e.g., 'namespace/discord_bot')

        Returns:
            Repository name without namespace prefix (e.g., 'discord_bot')
        """
        if not self.oci_namespace:
            return repository

        # If repository starts with namespace/, strip it
        namespace_prefix = f"{self.oci_namespace}/"
        if repository.startswith(namespace_prefix):
            normalized = repository[len(namespace_prefix):]
            logger.debug(f"Normalized OCIR repository: {repository} -> {normalized}")
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
        if not self.identity_client:
            return []

        tenancy_id = self._get_tenancy_id()
        if not tenancy_id:
            return []

        compartment_ids = [tenancy_id]  # Start with root tenancy

        try:
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

        except Exception as e:
            logger.warning(f"Failed to list compartments: {e}")
            # Fall back to just the tenancy root
            return [tenancy_id]

    def _find_repository_compartment(self, repository: str) -> Optional[str]:
        """Find which compartment contains the given repository.

        Args:
            repository: Repository name (e.g., 'discord-bot', without namespace)

        Returns:
            Compartment OCID where repository exists, or None if not found
        """
        # Normalize repository name (strip namespace if present)
        normalized_repo = self.normalize_ocir_repository(repository)

        # Check cache first (use normalized name)
        if normalized_repo in self._repository_compartment_cache:
            logger.debug(f"Using cached compartment for repository {normalized_repo}")
            return self._repository_compartment_cache[normalized_repo]

        if not self.artifacts_client:
            return None

        # Get all accessible compartments
        compartments = self._list_all_compartments()

        # Search each compartment for the repository
        for compartment_id in compartments:
            try:
                response = self.artifacts_client.list_container_images(
                    compartment_id=compartment_id,
                    repository_name=normalized_repo,
                    limit=1  # Just check if it exists
                )

                # If we got any results, this compartment has the repository
                if response.data.items:
                    logger.info(f"Found repository {normalized_repo} in compartment {compartment_id}")
                    # Cache the result
                    self._repository_compartment_cache[normalized_repo] = compartment_id
                    return compartment_id

            except oci.exceptions.ServiceError as e:
                # 404 means repository doesn't exist in this compartment, continue searching
                if e.status == 404:
                    continue
                # Other errors - log and continue
                logger.debug(f"Error checking compartment {compartment_id}: {e.message}")
                continue

        logger.warning(f"Repository {normalized_repo} not found in any accessible compartment")
        return None

    def _get_ocir_images_via_sdk(self, repository: str) -> list[dict]:
        """Get OCIR images using OCI SDK.

        Searches across all accessible compartments to find the repository.

        Args:
            repository: Repository name (e.g., 'discord-bot', with or without namespace)

        Returns:
            List of image dictionaries with version and created_at
        """
        # Normalize repository name (strip namespace if present)
        normalized_repo = self.normalize_ocir_repository(repository)

        # Check cache first (use normalized name)
        if normalized_repo in self._ocir_image_cache:
            logger.debug(f"Using cached OCIR image data for {normalized_repo}")
            return self._ocir_image_cache[normalized_repo]

        if not self.artifacts_client:
            logger.debug("OCI SDK client not available")
            return []

        # Find which compartment contains this repository
        compartment_id = self._find_repository_compartment(normalized_repo)
        if not compartment_id:
            logger.warning(f"Could not find compartment for repository {normalized_repo}")
            return []

        try:
            # List all container images in the repository
            response = self.artifacts_client.list_container_images(
                compartment_id=compartment_id,
                repository_name=normalized_repo
            )

            images = []
            for item in response.data.items:
                # Each item has version (tag) and time_created
                if item.version:
                    images.append({
                        'tag': item.version,
                        'created_at': item.time_created,
                        'digest': item.digest if hasattr(item, 'digest') else None
                    })

            # Cache the results
            self._ocir_image_cache[normalized_repo] = images
            logger.debug(f"Found {len(images)} OCIR images for {normalized_repo}")
            return images

        except oci.exceptions.ServiceError as e:
            logger.warning(f"OCI SDK error listing images for {normalized_repo}: {e.message}")
            return []
        except Exception as e:
            logger.warning(f"Failed to list OCIR images for {normalized_repo}: {e}")
            return []

    def get_image_manifest(self, registry: str, repository: str, tag: str) -> Optional[dict]:
        """Fetch image manifest from registry.

        Args:
            registry: Registry hostname
            repository: Image repository
            tag: Image tag

        Returns:
            Manifest data or None on error
        """
        # pylint: disable=too-many-return-statements
        with tracer.start_as_current_span("get-image-manifest") as span:
            span.set_attribute("registry", registry)
            span.set_attribute("repository", repository)
            span.set_attribute("tag", tag)

            try:
                # OCIR images use OCI SDK, not this method
                if self.is_ocir_image(registry):
                    logger.warning(f"get_image_manifest() should not be called for OCIR images: {repository}")
                    return None

                # Determine auth and URL based on registry
                if registry == "docker.io":
                    # Docker Hub uses different auth flow
                    token = self._get_dockerhub_token(repository)
                    url = f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}"
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.docker.distribution.manifest.v2+json",
                    }
                elif registry == "ghcr.io":
                    # GitHub Container Registry (public access)
                    url = f"https://{registry}/v2/{repository}/manifests/{tag}"
                    headers = {
                        "Accept": "application/vnd.docker.distribution.manifest.v2+json",
                    }
                else:
                    logger.warning(f"Unsupported registry: {registry}")
                    return None

                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                return response.json()

            except requests.exceptions.RequestException as e:
                logger.debug(f"Failed to fetch manifest for {registry}/{repository}:{tag}: {e}")
                span.set_attribute("error", str(e))
                return None

    def get_image_creation_date(self, registry: str, repository: str, tag: str) -> Optional[datetime]:
        """Get image creation date from manifest.

        Args:
            registry: Registry hostname
            repository: Image repository
            tag: Image tag

        Returns:
            Creation datetime or None
        """
        # pylint: disable=too-many-return-statements
        # For OCIR images, use cached SDK data
        if self.is_ocir_image(registry):
            images = self._get_ocir_images_via_sdk(repository)
            for img in images:
                if img['tag'] == tag and img.get('created_at'):
                    logger.debug(f"Using cached creation date for OCIR image {repository}:{tag}")
                    return img['created_at']
            logger.debug(f"No cached creation date found for OCIR image {repository}:{tag}")
            return None

        # For other registries, fetch manifest and extract creation date
        manifest = self.get_image_manifest(registry, repository, tag)
        if not manifest:
            return None

        try:
            # Get the config blob digest
            config_digest = manifest.get("config", {}).get("digest")
            if not config_digest:
                return None

            # Fetch the config blob
            # Note: OCIR images are handled above via OCI SDK, not here
            if registry == "docker.io":
                token = self._get_dockerhub_token(repository)
                url = f"https://registry-1.docker.io/v2/{repository}/blobs/{config_digest}"
                headers = {"Authorization": f"Bearer {token}"}
            elif registry == "ghcr.io":
                url = f"https://{registry}/v2/{repository}/blobs/{config_digest}"
                headers = {}
            else:
                return None

            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            config = response.json()

            # Parse creation date from config
            created_str = config.get("created")
            if created_str:
                # Parse ISO 8601 format
                return datetime.fromisoformat(created_str.replace('Z', '+00:00'))

        except Exception as e:
            logger.debug(f"Failed to get creation date for {registry}/{repository}:{tag}: {e}")

        return None

    def _get_dockerhub_token(self, repository: str) -> str:
        """Get authentication token for Docker Hub.

        Args:
            repository: Repository name

        Returns:
            Bearer token
        """
        # Docker Hub uses a separate auth endpoint
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("token", "")
        except Exception as e:
            logger.warning(f"Failed to get Docker Hub token: {e}")
            return ""

    def get_image_tags(self, registry: str, repository: str) -> list[str]:
        """Fetch all tags for a given image repository.

        Args:
            registry: Registry hostname
            repository: Image repository (e.g., 'namespace/discord-bot')

        Returns:
            List of tag names
        """
        with tracer.start_as_current_span("get-image-tags") as span:
            span.set_attribute("registry", registry)
            span.set_attribute("repository", repository)

            try:
                # Build URL and headers based on registry type
                if self.is_ocir_image(registry):
                    # Use OCI SDK for OCIR
                    images = self._get_ocir_images_via_sdk(repository)
                    if images:
                        tags = [img['tag'] for img in images]
                        span.set_attribute("registry.tags.count", len(tags))
                        logger.debug(f"Found {len(tags)} tags for {repository} via OCI SDK")
                        return tags
                    logger.warning(f"No images found for OCIR repository: {repository}")
                    return []

                if registry == "docker.io":
                    # Docker Hub API v2
                    url = f"https://hub.docker.com/v2/repositories/{repository}/tags?page_size=100"
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    tags = [result["name"] for result in data.get("results", [])]
                    span.set_attribute("registry.tags.count", len(tags))
                    logger.debug(f"Found {len(tags)} tags for {repository} on Docker Hub")
                    return tags

                if registry == "ghcr.io":
                    # GitHub Container Registry uses standard Docker v2 API
                    url = f"https://{registry}/v2/{repository}/tags/list"
                    headers = {}
                    logger.debug(f"Fetching tags for {repository} from {registry}")
                    response = requests.get(url, headers=headers, timeout=10)
                    response.raise_for_status()

                    data = response.json()
                    tags = data.get("tags", [])

                    span.set_attribute("registry.tags.count", len(tags))
                    logger.debug(f"Found {len(tags)} tags for {repository}")
                    return tags

                logger.warning(f"Unsupported registry: {registry}")
                return []

            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed to fetch tags for {registry}/{repository}: {e}")
                span.set_attribute("registry.error", str(e))
                return []

    @staticmethod
    def parse_version(tag: str) -> ImageVersion:
        """Parse a tag into a version object.

        Args:
            tag: Image tag (e.g., 'v1.2.3', '1.2.3', 'abc123')

        Returns:
            ImageVersion object with parsed components
        """
        match = RegistryClient.SEMVER_PATTERN.match(tag)

        if match:
            return ImageVersion(
                tag=tag,
                major=int(match.group(1)),
                minor=int(match.group(2)),
                patch=int(match.group(3)),
                is_semver=True,
            )

        return ImageVersion(tag=tag, is_semver=False)

    def get_latest_version(self, registry: str, repository: str, tags: list[str]) -> Optional[ImageVersion]:
        """Get the latest version from a list of tags.

        Args:
            registry: Registry hostname
            repository: Repository name
            tags: List of tag names

        Returns:
            Latest version (semver or by creation date)
        """
        semver_versions = []
        dated_versions = []

        for tag in tags:
            version = self.parse_version(tag)

            # Get creation date for all versions (needed for comparison)
            created_at = self.get_image_creation_date(registry, repository, tag)
            if created_at:
                version.created_at = created_at

            if version.is_semver:
                semver_versions.append(version)
            elif created_at:
                # Only add non-semver if it has a creation date
                dated_versions.append(version)

        # If we have only semver versions, use semver comparison
        if semver_versions and not dated_versions:
            return max(semver_versions)

        # If we have only dated non-semver versions, use date comparison
        if dated_versions and not semver_versions:
            return max(dated_versions, key=lambda v: v.created_at)

        # If we have both, compare by creation date to find truly latest
        if semver_versions and dated_versions:
            all_versions = semver_versions + dated_versions
            # Filter to only those with creation dates
            versions_with_dates = [v for v in all_versions if v.created_at]
            if versions_with_dates:
                return max(versions_with_dates, key=lambda v: v.created_at)

        return None

    def _find_alternate_tag(self, registry: str, repository: str, tags: list[str], target_date: datetime) -> Optional[str]:
        """Find a non-semver tag with the same creation timestamp.

        When displaying updates, if the latest is a semver tag but the current is a commit hash,
        this finds a commit hash tag that corresponds to the same image (same creation date).

        Args:
            registry: Registry hostname
            repository: Repository name
            tags: List of available tags
            target_date: Creation date to match

        Returns:
            Non-semver tag with matching creation date, or None
        """
        for tag in tags:
            version = self.parse_version(tag)
            # Skip semver tags, we're looking for commit hashes
            if version.is_semver:
                continue

            created_at = self.get_image_creation_date(registry, repository, tag)
            if created_at and created_at == target_date:
                logger.debug(f"Found alternate tag {tag} for timestamp {target_date}")
                return tag

        return None

    def check_for_updates(self, image: str) -> Optional[dict]:
        """Check if a newer version exists for the given image.

        Args:
            image: Full image name (e.g., 'iad.ocir.io/namespace/discord-bot:abc123')

        Returns:
            Dictionary with update information, or None if no updates available
        """
        with tracer.start_as_current_span("check-for-updates") as span:
            # Parse image name
            registry, repository, current_tag = self.parse_image_name(image)

            span.set_attribute("image.registry", registry)
            span.set_attribute("image.repository", repository)
            span.set_attribute("image.current_tag", current_tag)

            # Skip 'latest' tag - it's always the most recent by definition
            if current_tag == "latest":
                logger.debug(f"Skipping version check for {image} (latest tag)")
                span.set_attribute("update.check.skipped", True)
                span.set_attribute("update.skip_reason", "latest_tag")
                return None

            # Parse current version
            current_version = self.parse_version(current_tag)

            # Get current image creation date if not semver
            if not current_version.is_semver:
                current_created = self.get_image_creation_date(registry, repository, current_tag)
                if current_created:
                    current_version.created_at = current_created
                else:
                    logger.debug(f"Could not get creation date for {image}, skipping update check")
                    span.set_attribute("update.check.skipped", True)
                    return None

            # Fetch available tags
            available_tags = self.get_image_tags(registry, repository)

            if not available_tags:
                logger.warning(f"No tags found for {registry}/{repository}")
                span.set_attribute("update.check.failed", True)
                return None

            # Find latest version
            latest_version = self.get_latest_version(registry, repository, available_tags)

            if not latest_version:
                logger.debug(f"Could not determine latest version for {registry}/{repository}")
                span.set_attribute("update.check.no_versions", True)
                return None

            # Compare versions
            if latest_version > current_version:
                # Determine if it's a major update
                is_major_update = False
                major_diff = 0
                minor_diff = 0
                patch_diff = 0

                if current_version.is_semver and latest_version.is_semver:
                    is_major_update = latest_version.major > current_version.major
                    major_diff = latest_version.major - current_version.major
                    minor_diff = latest_version.minor - current_version.minor
                    patch_diff = latest_version.patch - current_version.patch

                # If current is non-semver and latest is semver, try to find a commit hash
                # tag with the same timestamp as the semver (for better display)
                alternate_tag = None
                if not current_version.is_semver and latest_version.is_semver and latest_version.created_at:
                    alternate_tag = self._find_alternate_tag(
                        registry, repository, available_tags, latest_version.created_at
                    )

                span.set_attribute("update.available", True)
                span.set_attribute("update.is_major", is_major_update)
                span.set_attribute("update.current_version", current_version.to_string())
                span.set_attribute("update.latest_version", latest_version.to_string())

                return {
                    "current": current_version,
                    "latest": latest_version,
                    "alternate_tag": alternate_tag,
                    "is_major_update": is_major_update,
                    "major_diff": major_diff,
                    "minor_diff": minor_diff,
                    "patch_diff": patch_diff,
                }

            span.set_attribute("update.available", False)
            return None

    def get_cleanup_recommendations(
        self, images: list[str], keep_count: int = 5
    ) -> dict[str, dict]:
        """Generate cleanup recommendations for OCIR repositories.

        Identifies old commit hash tags that can be deleted while keeping the most recent ones.

        Args:
            images: List of image names from Kubernetes deployments
            keep_count: Number of most recent commit hash tags to keep (default: 5)

        Returns:
            Dictionary mapping repository names to cleanup info:
            {
                'repository_name': {
                    'registry': 'iad.ocir.io',
                    'repository': 'namespace/myapp',
                    'tags_in_use': ['abc123', 'def456'],  # Tags currently deployed
                    'tags_to_keep': ['xyz789', ...],       # Recent tags to keep
                    'tags_to_delete': [                    # Tags that can be deleted
                        {'tag': 'old123', 'created_at': datetime(...), 'age_days': 45},
                        ...
                    ],
                    'total_deletable': 10,
                    'estimated_cleanup_gb': 2.5  # Estimated space saved (if available)
                }
            }
        """
        cleanup_recommendations = {}

        # Group images by OCIR repository
        ocir_repos = {}
        for image in images:
            registry, repository, tag = self.parse_image_name(image)

            # Only process OCIR images
            if not self.is_ocir_image(registry):
                continue

            repo_key = f"{registry}/{repository}"
            if repo_key not in ocir_repos:
                ocir_repos[repo_key] = {
                    'registry': registry,
                    'repository': repository,
                    'tags_in_use': set()
                }

            ocir_repos[repo_key]['tags_in_use'].add(tag)

        # For each OCIR repository, generate cleanup recommendations
        for repo_key, repo_info in ocir_repos.items():
            registry = repo_info['registry']
            repository = repo_info['repository']
            tags_in_use = repo_info['tags_in_use']

            # Get all available tags
            all_tags = self.get_image_tags(registry, repository)
            if not all_tags:
                continue

            # Filter to commit hash tags only (exclude semver and 'latest')
            commit_hash_tags = []
            for tag in all_tags:
                if tag == 'latest':
                    continue

                version = self.parse_version(tag)
                if version.is_semver:
                    continue

                # Get creation date
                created_at = self.get_image_creation_date(registry, repository, tag)
                if created_at:
                    commit_hash_tags.append({
                        'tag': tag,
                        'created_at': created_at,
                        'in_use': tag in tags_in_use
                    })

            # Sort by creation date (newest first)
            commit_hash_tags.sort(key=lambda x: x['created_at'], reverse=True)

            # Determine which tags to keep and which to delete
            tags_to_keep = []
            tags_to_delete = []
            non_in_use_kept = 0  # Track how many non-in-use tags we've kept

            for tag_info in commit_hash_tags:
                tag = tag_info['tag']
                created_at = tag_info['created_at']
                in_use = tag_info['in_use']

                # Always keep tags that are currently in use
                if in_use:
                    tags_to_keep.append(tag)
                # Keep the N most recent tags (excluding those in use)
                elif non_in_use_kept < keep_count:
                    tags_to_keep.append(tag)
                    non_in_use_kept += 1
                # Everything else can be deleted
                else:
                    age_days = (datetime.now(timezone.utc) - created_at).days
                    tags_to_delete.append({
                        'tag': tag,
                        'created_at': created_at,
                        'age_days': age_days
                    })

            # Only include repositories that have deletable tags
            if tags_to_delete:
                cleanup_recommendations[repo_key] = {
                    'registry': registry,
                    'repository': repository,
                    'tags_in_use': sorted(tags_in_use),
                    'tags_to_keep': sorted([t for t in tags_to_keep if t not in tags_in_use]),
                    'tags_to_delete': tags_to_delete,
                    'total_deletable': len(tags_to_delete)
                }

        return cleanup_recommendations

    def _delete_repository_tags(
        self, repository: str, tags_to_delete: list[dict]
    ) -> tuple[list[str], list[dict]]:
        """Delete tags for a single repository.

        Args:
            repository: Full repository name (e.g., 'namespace/myapp')
            tags_to_delete: List of tag info dicts with 'tag' and 'age_days'

        Returns:
            Tuple of (deleted_tags, failed_deletions)
        """
        deleted = []
        failed = []

        # Need to find the compartment for this repository
        repo_name = self.normalize_ocir_repository(repository)
        compartment_id = self._find_repository_compartment(repo_name)

        if not compartment_id:
            logger.warning(f"Could not find compartment for {repository}, skipping deletion")
            return deleted, failed

        # Get all images for this repository to find OCIDs
        images_in_repo = self._get_ocir_images_via_sdk(repo_name)

        for tag_info in tags_to_delete:
            tag = tag_info['tag']

            try:
                logger.info(f"Deleting {repository}:{tag} (age: {tag_info['age_days']} days)")

                # Find the image OCID for this tag
                image_id = None
                if images_in_repo:
                    for img in images_in_repo:
                        # Check if this image has the tag we want to delete
                        if hasattr(img, 'version') and img.version == tag:
                            image_id = img.id
                            break

                if not image_id:
                    error_msg = f"Could not find image OCID for tag {tag}"
                    failed.append({'tag': tag, 'error': error_msg})
                    logger.error(f"  └─ ✗ {error_msg}")
                    continue

                # Delete the image by OCID
                self.artifacts_client.delete_container_image(image_id)

                deleted.append(tag)
                logger.info(f"  └─ ✓ Successfully deleted {repository}:{tag}")

            except Exception as e:
                error_msg = str(e)
                failed.append({'tag': tag, 'error': error_msg})
                logger.error(f"  └─ ✗ Failed to delete {repository}:{tag}: {error_msg}")

        return deleted, failed

    def delete_ocir_images(self, cleanup_recommendations: dict[str, dict]) -> dict[str, dict]:
        """Delete old OCIR images based on cleanup recommendations.

        Args:
            cleanup_recommendations: Dictionary of cleanup recommendations from get_cleanup_recommendations()

        Returns:
            Dictionary mapping repository names to deletion results:
            {
                'repository_name': {
                    'repository': 'namespace/myapp',
                    'deleted': ['tag1', 'tag2'],  # Successfully deleted tags
                    'failed': [                    # Failed deletions with errors
                        {'tag': 'tag3', 'error': 'error message'},
                        ...
                    ],
                    'total_deleted': 2,
                    'total_failed': 1
                }
            }
        """
        if not self.artifacts_client:
            logger.warning("OCI SDK not available, cannot delete OCIR images")
            return {}

        deletion_results = {}

        for repo_key, rec in cleanup_recommendations.items():
            repository = rec['repository']
            tags_to_delete = rec['tags_to_delete']

            if not tags_to_delete:
                continue

            # Delete images for this repository
            deleted, failed = self._delete_repository_tags(repository, tags_to_delete)

            deletion_results[repo_key] = {
                'repository': repository,
                'deleted': deleted,
                'failed': failed,
                'total_deleted': len(deleted),
                'total_failed': len(failed)
            }

        return deletion_results
