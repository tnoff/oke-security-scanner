"""Main entry point for OKE Security Scanner."""

import sys
import logging
from logging import getLogger
from typing import Tuple, Optional

from opentelemetry.sdk._logs import LoggingHandler, LoggerProvider
from opentelemetry.sdk.trace import TracerProvider

from .config import Config
from .telemetry import setup_telemetry, create_metrics, Metrics
from .k8s_client import KubernetesClient
from .scanner import TrivyScanner, CompleteScanResult
from .discord_notifier import DiscordNotifier
from .registry_client import RegistryClient
from .oke_client import OKEClient


logger = getLogger(__name__)

def setup_otel(config: Config) -> Tuple[Optional[TracerProvider], Optional[LoggerProvider], Optional[Metrics]]:
    logger.debug("Initializing OpenTelemetry")
    trace_provider, meter_provider, logger_provider = setup_telemetry(config)

    # Add OTLP logging handler if logs are enabled
    if logger_provider:
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

    # Create metrics (returns None if meter_provider is None)
    scanner_metrics = create_metrics(meter_provider)
    return trace_provider, logger_provider, scanner_metrics

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
    trace_provider = None
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
        trace_provider, logger_provider, scanner_metrics = setup_otel(config)
        scanner = TrivyScanner(config, logger_provider)
        logger.info("Updating Trivy vulnerability database...")
        db_updated = scanner.update_database()
        if db_updated:
            logger.info("Trivy database updated successfully")
        else:
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

        if config.discord_webhook_url:
            logger.debug("Sending Discord webhook notification...")
            notifier = DiscordNotifier(config.discord_webhook_url)
            notifier.send_image_scan_report(scan_results)

        if scanner_metrics:
            logger.info('Sending out scan metrics')
            send_scan_metrics(scanner_metrics, scan_results)


        logger.info("Checking for image version updates")
        registry_client = RegistryClient(config)

        update_results = registry_client.check_image_updates(images)

        if config.discord_webhook_url:
            logger.debug("Sending Discord webhook notification...")
            notifier = DiscordNotifier(config.discord_webhook_url)
            notifier.send_version_update_info(update_results)
        logger.info("Checking for OCIR cleanup recommendations...")
        registry_client = RegistryClient(config)
        cleanup_recommendations = registry_client.get_old_ocir_images(
            images, keep_count=config.ocir_cleanup_keep_count,
            extra_repositories=config.ocir_extra_repositories,
        )
        if config.discord_webhook_url:
            logger.debug("Sending Discord webhook notification...")
            notifier = DiscordNotifier(config.discord_webhook_url)
            notifier.send_cleanup_recommendations(cleanup_recommendations)
        if config.ocir_cleanup_enabled:
            deletion_results = registry_client.delete_ocir_images(cleanup_recommendations)
            if config.discord_webhook_url:
                logger.debug("Sending Discord webhook notification...")
                notifier = DiscordNotifier(config.discord_webhook_url)
                notifier.send_deletion_results(deletion_results)

        # Check for OKE node image updates (if enabled)
        if config.oke_image_check_enabled:
            logger.info("Checking for OKE node image updates...")
            oke_client = OKEClient(config)
            node_image_updates = oke_client.check_for_updates()

            if node_image_updates:
                logger.info(f"Found {len(node_image_updates)} node pool(s) with updates available")
            else:
                logger.info("All node pools are up to date")

            if config.discord_webhook_url:
                logger.debug("Sending Discord webhook notification...")
                notifier = DiscordNotifier(config.discord_webhook_url)
                notifier.send_node_image_report(node_image_updates)

        logger.info("Scan completed successfully")

    finally:
        # Properly shutdown telemetry to flush all pending data
        logger.info("Shutting down telemetry...")

        # Use providers from setup_telemetry (will be None if disabled)
        if trace_provider:
            logger.debug("Flushing traces...")
            trace_provider.force_flush(timeout_millis=30000)
            trace_provider.shutdown()
            logger.debug("Traces flushed")

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


if __name__ == "__main__":
    main()
