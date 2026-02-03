"""Kubernetes client for discovering deployed images."""

from datetime import datetime
from dataclasses import dataclass, field
from logging import getLogger
import re
from typing import Self, Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from opentelemetry.sdk._logs import LoggingHandler
from opentelemetry import trace

from .config import Config

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)

# Semver regex pattern (supports v1.2.3 or 1.2.3 format, or 3.4)
SEMVER_PATTERN = re.compile(r'^v?(\d+)\.(\d+)\.?(\d+)?$')
GITHASH_PATTERN = re.compile(r'^[a-zA-Z0-9]{7}$')

OTEL_PREFIX = 'k8s'

@dataclass(unsafe_hash=True)
class ImageVersion:
    """Represents a parsed image version."""

    tag: str
    major: Optional[int] = None
    minor: Optional[int] = None
    patch: Optional[int] = None
    is_semver: bool = False
    is_githash: bool = False

    def __lt__(self, other: Self) -> bool:
        """Compare versions for sorting."""
        if not self.is_semver:
            return self.tag < other.tag
        if self.major > other.major:
            return False
        if self.major < other.major:
            return True
        if self.minor > other.minor:
            return False
        if self.minor < other.minor:
            return True
        if self.patch > other.patch:
            return False
        if self.patch < other.patch:
            return True
        return True

    def __eq__(self, other: Self) -> bool:
        """Check version equality."""
        if not self.is_semver:
            return self.tag == other.tag
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __str__(self) -> str:
        """Convert version to string representation."""
        if self.is_semver:
            return f"{self.major}.{self.minor}.{self.patch}"
        return self.tag

@dataclass(unsafe_hash=True)
class Image:
    '''Base image'''
    full_name: str
    # Ocid if ocir image
    ocid: str = None
    created_at: datetime = None
    repo_name: str = field(init=False)
    tag: str = field(init=False)
    registry: str = field(init=False)
    version: ImageVersion = field(init=False)

    def __parse_version(self) -> ImageVersion:
        """Parse a tag into a version object."""
        match = SEMVER_PATTERN.match(self.tag)
        if match:
            # Patch is an optional parameter
            patch = 0
            try:
                patch = int(match.group(3))
            except TypeError:
                pass
            if not patch:
                patch = 0
            return ImageVersion(
                tag=self.tag,
                major=int(match.group(1)),
                minor=int(match.group(2)),
                patch=patch,
                is_semver=True,
            )
        match = GITHASH_PATTERN.match(self.tag)
        if match:
            return ImageVersion(self.tag, is_githash=True)
        return ImageVersion(tag=self.tag)

    def __post_init__(self):
        # Init the rest
        parsed = self.full_name.split(':')
        self.tag = parsed[1]
        self.repo_name = parsed[0]
        if self.full_name.count('/') < 2:
            self.registry = "docker.io"
        else:
            repo_parsed = parsed[0].split('/')
            self.repo_name = '/'.join(i for i in repo_parsed[1:])
            self.registry = repo_parsed[0]
        self.version = self.__parse_version()

    def __eq__(self, value: Self) -> bool:
        return self.full_name == value.full_name

    def __lt__(self, value: Self) -> bool:
        if self.version.is_semver and value.version.is_semver:
            return self.version < value.version
        if self.created_at and value.created_at:
            return self.created_at < value.created_at
        return self.full_name < value.full_name

    def __str__(self):
        return self.full_name

    @property
    def is_ocir_image(self) -> bool:
        '''Check if ocir registry'''
        return 'ocir' in self.registry

class KubernetesClient:
    """Client for interacting with Kubernetes API."""

    def __init__(self, cfg: Config, logger_provider):
        """Initialize Kubernetes client."""
        self.cfg = cfg
        if logger_provider:
            logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

        try:
            # Load in-cluster config (when running in K8s)
            config.load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes configuration")
        except config.ConfigException:
            # Fallback to kubeconfig (for local development)
            config.load_kube_config()
            logger.info("Loaded kubeconfig from local environment")

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()

    def get_all_images(self) -> set[Image]:
        """Get all unique container images deployed in the cluster."""
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_images') as span:
            images = set()

            try:
                # Get all namespaces
                namespaces = self._get_namespaces()
                logger.info(f"Found {len(namespaces)} namespaces: {namespaces}")

                # Get images from pods in each namespace
                for namespace in namespaces:
                    namespace_images = self._get_namespace_images(namespace)
                    images.update(namespace_images)
                    logger.info(f"Found {len(namespace_images)} images in namespace {namespace}")

            except ApiException as e:
                logger.error(f"Kubernetes API error (status {e.status}): {e}")
                span.record_exception(e)
                raise

            logger.info(f"Total unique images discovered: {len(images)}")
            return images

    def _get_namespaces(self) -> list[str]:
        """Get list of namespaces to scan."""
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_namespaces'):
            # If specific namespaces configured, use those
            if self.cfg.namespaces:
                return self.cfg.namespaces

            # Otherwise, get all namespaces and filter exclusions
            all_namespaces = self.core_v1.list_namespace()
            namespaces = [
                ns.metadata.name
                for ns in all_namespaces.items
                if ns.metadata.name not in self.cfg.exclude_namespaces
            ]
            return namespaces

    def _get_namespace_images(self, namespace: str) -> set[Image]:
        """Get all container images in a specific namespace."""
        with tracer.start_as_current_span(f'{OTEL_PREFIX}.get_namespace_images') as span:
            span.set_attribute("k8s.namespace", namespace)
            images = set()

            try:
                # Get all pods in namespace
                pods = self.core_v1.list_namespaced_pod(namespace)
                span.set_attribute("k8s.pods.count", len(pods.items))

                # Extract container images
                for pod in pods.items:
                    # Regular containers
                    if pod.spec.containers:
                        for container in pod.spec.containers:
                            if container.image:
                                images.add(Image(container.image))

                    # Init containers
                    if pod.spec.init_containers:
                        for container in pod.spec.init_containers:
                            if container.image:
                                images.add(Image(container.image))

            except ApiException as e:
                logger.warning(f"Failed to get pods in namespace {namespace}: {e}")
                span.record_exception(e)
            return images
