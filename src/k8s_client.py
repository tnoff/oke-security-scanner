"""Kubernetes client for discovering deployed images."""

from logging import getLogger

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from opentelemetry.sdk._logs import LoggingHandler
from opentelemetry import trace

from .config import Config

logger = getLogger(__name__)
tracer = trace.get_tracer(__name__)


class KubernetesClient:
    """Client for interacting with Kubernetes API."""

    def __init__(self, cfg: Config, logger_provider):
        """Initialize Kubernetes client."""
        self.cfg = cfg
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

        with tracer.start_as_current_span("init-k8s-client") as span:
            try:
                # Load in-cluster config (when running in K8s)
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes configuration")
                span.set_attribute("k8s.config.type", "incluster")
            except config.ConfigException:
                # Fallback to kubeconfig (for local development)
                config.load_kube_config()
                logger.info("Loaded kubeconfig from local environment")
                span.set_attribute("k8s.config.type", "kubeconfig")

            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            span.set_attribute("k8s.init.success", True)

    def get_all_images(self) -> set[str]:
        """Get all unique container images deployed in the cluster."""
        with tracer.start_as_current_span("get-all-images") as span:
            images = set()

            try:
                # Get all namespaces
                namespaces = self._get_namespaces()
                span.set_attribute("k8s.namespaces.count", len(namespaces))
                logger.info("Found namespaces", count=len(namespaces), namespaces=namespaces)

                # Get images from pods in each namespace
                for namespace in namespaces:
                    namespace_images = self._get_namespace_images(namespace)
                    images.update(namespace_images)
                    logger.info(
                        "Found images in namespace",
                        namespace=namespace,
                        count=len(namespace_images),
                    )

                span.set_attribute("k8s.images.total", len(images))
                span.set_attribute("k8s.operation.success", True)

            except ApiException as e:
                logger.error("Kubernetes API error", error=str(e), status=e.status)
                span.set_attribute("k8s.operation.success", False)
                span.set_attribute("k8s.operation.error", str(e))
                raise

            logger.info("Total unique images discovered", count=len(images))
            return images

    def _get_namespaces(self) -> list[str]:
        """Get list of namespaces to scan."""
        with tracer.start_as_current_span("get-namespaces") as span:
            # If specific namespaces configured, use those
            if self.cfg.namespaces:
                span.set_attribute("k8s.namespaces.source", "configured")
                span.set_attribute("k8s.namespaces.count", len(self.cfg.namespaces))
                return self.cfg.namespaces

            # Otherwise, get all namespaces and filter exclusions
            all_namespaces = self.core_v1.list_namespace()
            namespaces = [
                ns.metadata.name
                for ns in all_namespaces.items
                if ns.metadata.name not in self.cfg.exclude_namespaces
            ]
            span.set_attribute("k8s.namespaces.source", "discovered")
            span.set_attribute("k8s.namespaces.total", len(all_namespaces.items))
            span.set_attribute("k8s.namespaces.excluded", len(self.cfg.exclude_namespaces))
            span.set_attribute("k8s.namespaces.count", len(namespaces))
            return namespaces

    def _get_namespace_images(self, namespace: str) -> set[str]:
        """Get all container images in a specific namespace."""
        with tracer.start_as_current_span("get-namespace-images") as span:
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
                                images.add(container.image)

                    # Init containers
                    if pod.spec.init_containers:
                        for container in pod.spec.init_containers:
                            if container.image:
                                images.add(container.image)

                span.set_attribute("k8s.images.count", len(images))
                span.set_attribute("k8s.operation.success", True)

            except ApiException as e:
                logger.warning(
                    "Failed to get pods in namespace",
                    namespace=namespace,
                    error=str(e),
                )
                span.set_attribute("k8s.operation.success", False)
                span.set_attribute("k8s.operation.error", str(e))

            return images
