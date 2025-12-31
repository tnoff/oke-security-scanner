"""OCIR registry client for fetching available image tags."""

import base64
import re
from logging import getLogger
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

import requests
from opentelemetry import trace

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
            return (datetime.now() - self.created_at).days
        return None


class RegistryClient:
    """Client for interacting with container registry APIs."""

    # Semver regex pattern (supports v1.2.3 or 1.2.3 format)
    SEMVER_PATTERN = re.compile(r'^v?(\d+)\.(\d+)\.(\d+).*$')

    def __init__(self, cfg: Config):
        """Initialize registry client."""
        self.cfg = cfg
        self.oci_registry = cfg.oci_registry
        self.oci_username = f"{cfg.oci_namespace}/{cfg.oci_username}"
        self.oci_password = cfg.oci_token

        # Create auth header for OCIR API
        auth_string = f"{self.oci_username}:{self.oci_password}"
        auth_token = base64.b64encode(auth_string.encode()).decode()
        self.oci_auth_header = f"Basic {auth_token}"

    @staticmethod
    def parse_image_name(image: str) -> Tuple[str, str, str]:
        """Parse image name into registry, repository, and tag.

        Args:
            image: Full image name (e.g., 'iad.ocir.io/tnoff/discord-bot:abc123')

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
            # Has explicit registry (e.g., 'iad.ocir.io/tnoff/discord-bot')
            registry, repository = parts
        else:
            # No explicit registry, assume Docker Hub
            registry = 'docker.io'
            repository = image_path

        return registry, repository, tag

    def is_ocir_image(self, registry: str) -> bool:
        """Check if registry is OCIR."""
        return registry == self.oci_registry

    def get_image_manifest(self, registry: str, repository: str, tag: str) -> Optional[dict]:
        """Fetch image manifest from registry.

        Args:
            registry: Registry hostname
            repository: Image repository
            tag: Image tag

        Returns:
            Manifest data or None on error
        """
        with tracer.start_as_current_span("get-image-manifest") as span:
            span.set_attribute("registry", registry)
            span.set_attribute("repository", repository)
            span.set_attribute("tag", tag)

            try:
                # Determine auth and URL based on registry
                if self.is_ocir_image(registry):
                    url = f"https://{registry}/v2/{repository}/manifests/{tag}"
                    headers = {
                        "Authorization": self.oci_auth_header,
                        "Accept": "application/vnd.docker.distribution.manifest.v2+json",
                    }
                elif registry == "docker.io":
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
        manifest = self.get_image_manifest(registry, repository, tag)
        if not manifest:
            return None

        try:
            # Get the config blob digest
            config_digest = manifest.get("config", {}).get("digest")
            if not config_digest:
                return None

            # Fetch the config blob
            if self.is_ocir_image(registry):
                url = f"https://{registry}/v2/{repository}/blobs/{config_digest}"
                headers = {"Authorization": self.oci_auth_header}
            elif registry == "docker.io":
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
            repository: Image repository (e.g., 'tnoff/discord-bot')

        Returns:
            List of tag names
        """
        with tracer.start_as_current_span("get-image-tags") as span:
            span.set_attribute("registry", registry)
            span.set_attribute("repository", repository)

            try:
                # Build URL and headers based on registry type
                if self.is_ocir_image(registry):
                    url = f"https://{registry}/v2/{repository}/tags/list"
                    headers = {"Authorization": self.oci_auth_header}
                elif registry == "docker.io":
                    # Docker Hub API v2
                    url = f"https://hub.docker.com/v2/repositories/{repository}/tags?page_size=100"
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    tags = [result["name"] for result in data.get("results", [])]
                    span.set_attribute("registry.tags.count", len(tags))
                    logger.debug(f"Found {len(tags)} tags for {repository} on Docker Hub")
                    return tags
                elif registry == "ghcr.io":
                    # GitHub Container Registry uses standard Docker v2 API
                    url = f"https://{registry}/v2/{repository}/tags/list"
                    headers = {}
                else:
                    logger.warning(f"Unsupported registry: {registry}")
                    return []

                logger.debug(f"Fetching tags for {repository} from {registry}")
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()

                data = response.json()
                tags = data.get("tags", [])

                span.set_attribute("registry.tags.count", len(tags))
                logger.debug(f"Found {len(tags)} tags for {repository}")

                return tags

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

            if version.is_semver:
                semver_versions.append(version)
            else:
                # For non-semver tags, get creation date
                created_at = self.get_image_creation_date(registry, repository, tag)
                if created_at:
                    version.created_at = created_at
                    dated_versions.append(version)

        # Prefer semver if available
        if semver_versions:
            return max(semver_versions)

        # Fall back to creation date
        if dated_versions:
            return max(dated_versions, key=lambda v: v.created_at)

        return None

    def check_for_updates(self, image: str) -> Optional[dict]:
        """Check if a newer version exists for the given image.

        Args:
            image: Full image name (e.g., 'iad.ocir.io/tnoff/discord-bot:abc123')

        Returns:
            Dictionary with update information, or None if no updates available
        """
        with tracer.start_as_current_span("check-for-updates") as span:
            # Parse image name
            registry, repository, current_tag = self.parse_image_name(image)

            span.set_attribute("image.registry", registry)
            span.set_attribute("image.repository", repository)
            span.set_attribute("image.current_tag", current_tag)

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

                span.set_attribute("update.available", True)
                span.set_attribute("update.is_major", is_major_update)
                span.set_attribute("update.current_version", current_version.to_string())
                span.set_attribute("update.latest_version", latest_version.to_string())

                return {
                    "current": current_version,
                    "latest": latest_version,
                    "is_major_update": is_major_update,
                    "major_diff": major_diff,
                    "minor_diff": minor_diff,
                    "patch_diff": patch_diff,
                }

            span.set_attribute("update.available", False)
            return None
