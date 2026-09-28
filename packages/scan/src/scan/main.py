"""Main entry point for the vulnerability scan."""

import sys
import logging
from logging import getLogger
from typing import Tuple, Optional

from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.instrumentation.logging.handler import LoggingHandler
from oke_scanner_core.image import Image
from oke_scanner_core.k8s_client import KubernetesClient

from .config import Config
from .telemetry import setup_telemetry, shutdown_telemetry, create_metrics, Metrics
from .scanner import TrivyScanner, CompleteScanResult
from .discord_notifier import DiscordNotifier


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
    """Run the Trivy scan phase and return the discovered image set."""
    scanner = TrivyScanner(config, logger_provider)
    logger.info("Updating Trivy vulnerability database...")
    if not scanner.update_database():
        logger.warning("Trivy database update failed, using cached database")

    logger.debug("Initializing Kubernetes client")
    k8s_client = KubernetesClient(config.namespaces, config.exclude_namespaces, logger_provider)

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

    logger.debug("Loading configuration from environment variables")
    config = Config.from_env()

    try:
        meter_provider, logger_provider, scanner_metrics = setup_otel(config)
        notifier = DiscordNotifier(config.discord_webhook_url) if config.discord_webhook_url else None

        run_scan(config, logger_provider, scanner_metrics, notifier)

        logger.info("Run completed successfully")

    finally:
        shutdown_telemetry(meter_provider, logger_provider, logger)


if __name__ == "__main__":  # pragma: no cover
    main()
