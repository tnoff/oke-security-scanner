"""Main entry point for OKE Security Scanner."""

import sys
import logging
from logging import getLogger
from typing import Tuple, Optional

from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.instrumentation.logging.handler import LoggingHandler

from .config import Config
from .telemetry import setup_telemetry, create_metrics, Metrics
from .k8s_client import KubernetesClient, Image
from .scanner import TrivyScanner, CompleteScanResult
from .discord_notifier import DiscordNotifier
from .registry_client import RegistryClient


logger = getLogger(__name__)

def setup_otel(config: Config) -> Tuple[Optional[MeterProvider], Optional[LoggerProvider], Optional[Metrics]]:
    logger.debug("Initializing OpenTelemetry")
    meter_provider, logger_provider = setup_telemetry(config)

    # Add OTLP logging handler if logs are enabled
    if logger_provider:
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

    # Create metrics (returns None if meter_provider is None)
    scanner_metrics = create_metrics(meter_provider)
    return meter_provider, logger_provider, scanner_metrics

def send_scan_metrics(metric_provider: Metrics, scan_results: CompleteScanResult):
    '''Send otel metrics from scan result'''
    for scan in scan_results.scan_results:
        metric_provider.scan_total.set(scan.critical_count, {
            'image': scan.image.repo_name,
            'severity': 'critical',
        })
        metric_provider.scan_total.set(scan.high_count, {
            'image': scan.image.repo_name,
            'severity': 'high',
        })

def run_scan(
    config: Config,
    logger_provider: Optional[LoggerProvider],
    scanner_metrics: Optional[Metrics],
    notifier: Optional[DiscordNotifier],
) -> set[Image]:
    """Run the Trivy scan phase and return the discovered image set.

    The returned set is reused by the cleanup phase (so we don't list
    pods twice when both phases run in the same Job).
    """
    scanner = TrivyScanner(config, logger_provider)
    logger.info("Updating Trivy vulnerability database...")
    if not scanner.update_database():
        logger.warning("Trivy database update failed, using cached database")

    logger.debug("Initializing Kubernetes client")
    k8s_client = KubernetesClient(config, logger_provider)

    logger.info("Discovering deployed container images...")
    images = k8s_client.get_all_images()
    logger.info(f"Beginning vulnerability scans ({len(images)} images)")
    scan_results = CompleteScanResult()

    for idx, image in enumerate(sorted(images), 1):
        logger.info(f"[{idx}/{len(images)}] Scanning: {image.full_name}")
        result = scanner.scan_image(image)
        scan_results.add_result(result, image)

    if notifier:
        logger.debug("Sending Discord webhook notification...")
        notifier.send_image_scan_report(scan_results)

    if scanner_metrics:
        logger.info('Sending out scan metrics')
        send_scan_metrics(scanner_metrics, scan_results)

    return images

def run_cleanup(
    config: Config,
    logger_provider: Optional[LoggerProvider],
    notifier: Optional[DiscordNotifier],
    discovered_images: Optional[set[Image]] = None,
):
    """Run the OCIR tag + orphan-manifest cleanup phase.

    If ``CLEANUP_REPO`` is set, the cleanup is scoped to that single
    OCIR repo (used by producer pipelines that fire a one-off Job after
    pushing). Otherwise it sweeps every deployed image. ``discovered_images``
    is passed by ``run_scan`` to avoid re-listing pods.
    """
    if discovered_images is None:
        k8s_client = KubernetesClient(config, logger_provider)
        discovered_images = k8s_client.get_all_images()

    if config.cleanup_repo:
        logger.info(f"Cleanup scoped to repo: {config.cleanup_repo}")
        images = {
            im for im in discovered_images
            if im.is_ocir_image and im.repo_name == config.cleanup_repo
        }
        # Always include the target repo in extras so cleanup runs even if
        # nothing is currently deployed (e.g. first push of a new repo).
        extras = [config.cleanup_repo]
    else:
        images = discovered_images
        extras = config.ocir_extra_repositories

    registry_client = RegistryClient(config)

    logger.info("Checking for OCIR cleanup recommendations...")
    cleanup_recommendations = registry_client.get_old_ocir_images(
        images, keep_count=config.ocir_cleanup_keep_count,
        extra_repositories=extras,
    )
    if config.ocir_cleanup_enabled:
        deletion_results = registry_client.delete_ocir_images(cleanup_recommendations)
        if notifier:
            logger.debug("Sending Discord webhook notification...")
            notifier.send_deletion_results(deletion_results)
    elif notifier:
        logger.debug("Sending Discord webhook notification...")
        notifier.send_cleanup_recommendations(cleanup_recommendations)

    logger.info("Checking for orphaned platform manifests...")
    orphan_recommendations = registry_client.get_orphaned_manifests(
        images, extra_repositories=extras,
    )
    for rec in orphan_recommendations:
        logger.info(f"Found {len(rec.tags_to_delete)} orphaned manifests in {rec.repository}")

    if config.ocir_cleanup_enabled:
        orphans_deleted = registry_client.delete_ocir_images(orphan_recommendations)
        if orphans_deleted:
            logger.info(f"Deleted {len(orphans_deleted)} orphaned platform manifests")
        if notifier:
            logger.debug("Sending Discord webhook notification...")
            notifier.send_deletion_results(orphans_deleted, is_orphaned=True)

def main():
    """Run the security scanner."""
    # Configure logging to DEBUG level and output to stdout
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger.info("Initializing OKE Security Scanner")

    # Initialize providers as None so they're accessible in finally block
    meter_provider = None
    logger_provider = None

    try:
        # Load configuration
        logger.debug("Loading configuration from environment variables")
        config = Config.from_env()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    try:
        meter_provider, logger_provider, scanner_metrics = setup_otel(config)
        notifier = DiscordNotifier(config.discord_webhook_url) if config.discord_webhook_url else None

        discovered_images = None
        if config.enable_scan:
            discovered_images = run_scan(config, logger_provider, scanner_metrics, notifier)
        else:
            logger.info("ENABLE_SCAN=false — skipping Trivy scan phase")

        if config.enable_cleanup:
            run_cleanup(config, logger_provider, notifier, discovered_images)
        else:
            logger.info("ENABLE_CLEANUP=false — skipping OCIR cleanup phase")

        logger.info("Run completed successfully")

    finally:
        # Properly shutdown telemetry to flush all pending data
        logger.info("Shutting down telemetry...")

        # Use providers from setup_telemetry (will be None if disabled)
        if meter_provider:
            logger.debug("Flushing metrics...")
            meter_provider.force_flush(timeout_millis=30000)
            meter_provider.shutdown()
            logger.debug("Metrics flushed")

        if logger_provider:
            logger.debug("Flushing logs...")
            logger_provider.force_flush(timeout_millis=30000)
            logger_provider.shutdown()
            logger.debug("Logs flushed")

        logger.info("Telemetry shutdown complete")


if __name__ == "__main__":  # pragma: no cover
    main()
