"""Kubernetes client for discovering deployed images."""

from datetime import datetime
from dataclasses import dataclass, field
from logging import getLogger
from typing import Self

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from opentelemetry.instrumentation.logging.handler import LoggingHandler

from .config import Config

logger = getLogger(__name__)

@dataclass(unsafe_hash=True)
class Image:
    '''Base image'''
    full_name: str
    # Ocid if ocir image
    ocid: str = None
    created_at: datetime = None
    digest: str = None
    repo_name: str = field(init=False)
    tag: str = field(init=False)
    registry: str = field(init=False)

    def __post_init__(self):
        # Init the rest
        parsed = self.full_name.split(':')
        # Strip digest (@sha256:...) from the tag if present
        self.tag = parsed[1].split('@')[0]
        self.repo_name = parsed[0]
        if self.full_name.count('/') < 2:
            self.registry = "docker.io"
        else:
            repo_parsed = parsed[0].split('/')
            self.repo_name = '/'.join(i for i in repo_parsed[1:])
            self.registry = repo_parsed[0]

    def __eq__(self, value: Self) -> bool:
        return self.full_name == value.full_name

    def __lt__(self, value: Self) -> bool:
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

        # kubernetes==36.0.0 regression: load_*_config() stores the bearer
        # token under api_key['authorization'], but the generated API methods
        # look it up under the 'BearerToken' security-scheme key, so no
        # Authorization header gets sent and every call 401s. Mirror the
        # value across until upstream ships a fix.
        default_cfg = client.Configuration.get_default_copy()
        if default_cfg.api_key.get('authorization') and not default_cfg.api_key.get('BearerToken'):
            default_cfg.api_key['BearerToken'] = default_cfg.api_key['authorization']
            client.Configuration.set_default(default_cfg)

        self.core_v1 = client.CoreV1Api()

    def get_all_images(self) -> set[Image]:
        """Get all unique container images deployed in the cluster."""
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
            raise

        logger.info(f"Total unique images discovered: {len(images)}")
        return images

    def _get_namespaces(self) -> list[str]:
        """Get list of namespaces to scan."""
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
        images = set()

        try:
            # Get all pods in namespace
            pods = self.core_v1.list_namespaced_pod(namespace)

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
            logger.info(f"Failed to get pods in namespace {namespace}: {e}")
        return images
