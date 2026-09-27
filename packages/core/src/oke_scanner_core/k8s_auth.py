"""Kubernetes client bootstrap shared by every package that talks to the
k8s API: in-cluster config, falling back to local kubeconfig for dev.
"""

from logging import getLogger

from kubernetes import config as k8s_config

logger = getLogger(__name__)


def load_k8s_config() -> None:
    """Load in-cluster config, falling back to local kubeconfig."""
    try:
        k8s_config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes configuration")
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
        logger.info("Loaded kubeconfig from local environment")
