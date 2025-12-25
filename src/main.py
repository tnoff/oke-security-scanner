"""Main entry point for OKE Security Scanner."""

import sys
import time
import logging
from logging import getLogger

from opentelemetry import trace, metrics
from opentelemetry.sdk._logs import LoggingHandler

from .config import Config
from .telemetry import setup_telemetry, create_metrics
from .k8s_client import KubernetesClient
from .scanner import TrivyScanner


logger = getLogger(__name__)

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

    logger.info("=" * 60)
    logger.info("Starting OKE Security Scanner")
    logger.info("=" * 60)

    logger_provider = None

    try:
        # Load configuration
        logger.debug("Loading configuration from environment variables")
        config = Config.from_env()
        config.validate()
        logger.info("✓ Configuration loaded successfully")
        logger.debug(f"  - OTLP endpoint: {config.otlp_endpoint}")
        logger.debug(f"  - Trivy timeout: {config.trivy_timeout}s")
        logger.debug(f"  - Severity filter: {config.trivy_severity}")

        # Setup OpenTelemetry
        logger.debug("Initializing OpenTelemetry")
        trace_provider, meter_provider, logger_provider = setup_telemetry()
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))
        scanner_metrics = create_metrics(meter_provider)
        logger.info(f"✓ OpenTelemetry initialized (endpoint: {config.otlp_endpoint})")

        # Start root trace span
        with trace_provider.start_as_current_span("security-scan") as root_span:
            start_time = time.time()
            logger.info("-" * 60)
            logger.info("Starting security scan")
            logger.info("-" * 60)

            # Initialize scanner
            logger.debug("Initializing Trivy scanner")
            scanner = TrivyScanner(config, scanner_metrics, logger_provider)
            logger.info("✓ Trivy scanner initialized")

            # Update Trivy database
            logger.info("Updating Trivy vulnerability database...")
            db_updated = scanner.update_database()
            root_span.set_attribute("trivy.db_updated", db_updated)
            if db_updated:
                logger.info("✓ Trivy database updated successfully")
            else:
                logger.warning("⚠ Trivy database update failed, using cached database")

            # Initialize Kubernetes client
            logger.debug("Initializing Kubernetes client")
            k8s_client = KubernetesClient(config, logger_provider)
            logger.info("✓ Kubernetes client initialized")

            # Get all deployed images
            logger.info("Discovering deployed container images...")
            with trace_provider.start_as_current_span("get-cluster-images") as span:
                images = k8s_client.get_all_images()
                span.set_attribute("images.total", len(images))
                logger.info(f"✓ Discovered {len(images)} unique images across the cluster")

            # Scan each image
            logger.info("-" * 60)
            logger.info(f"Beginning vulnerability scans ({len(images)} images)")
            logger.info("-" * 60)

            scan_results = []
            total_critical = 0
            total_high = 0
            failed_scans = 0

            for idx, image in enumerate(sorted(images), 1):
                logger.info(f"[{idx}/{len(images)}] Scanning: {image}")
                result = scanner.scan_image(image)
                if result:
                    scan_results.append(result)
                    critical = result["vulnerabilities"].get("CRITICAL", 0)
                    high = result["vulnerabilities"].get("HIGH", 0)
                    total_critical += critical
                    total_high += high

                    if critical > 0 or high > 0:
                        logger.warning(f"  └─ Found {critical} CRITICAL, {high} HIGH vulnerabilities")
                    else:
                        logger.info("  └─ ✓ No critical/high vulnerabilities")
                else:
                    failed_scans += 1
                    logger.error("  └─ ✗ Scan failed")

            # Calculate total duration
            total_duration = time.time() - start_time

            # Log summary
            logger.info("=" * 60)
            logger.info("Security Scan Summary")
            logger.info("=" * 60)
            logger.info(f"  Total duration:        {round(total_duration, 2)}s")
            logger.info(f"  Images discovered:     {len(images)}")
            logger.info(f"  Successfully scanned:  {len(scan_results)}")
            logger.info(f"  Failed scans:          {failed_scans}")
            logger.info(f"  CRITICAL vulns found:  {total_critical}")
            logger.info(f"  HIGH vulns found:      {total_high}")
            logger.info("=" * 60)

            # Set root span attributes
            root_span.set_attribute("scan.images.total", len(images))
            root_span.set_attribute("scan.images.scanned", len(scan_results))
            root_span.set_attribute("scan.images.failed", failed_scans)
            root_span.set_attribute("scan.vulnerabilities.critical", total_critical)
            root_span.set_attribute("scan.vulnerabilities.high", total_high)

            # Exit with error if critical vulnerabilities found
            if total_critical > 0:
                logger.error("✗ CRITICAL VULNERABILITIES DETECTED!")
                logger.error(f"  Found {total_critical} critical vulnerabilities")
                logger.error("  Exiting with error code 1")
                root_span.set_attribute("scan.has_critical", True)
                sys.exit(1)

            logger.info("✓ No critical vulnerabilities found - scan passed")
            root_span.set_attribute("scan.has_critical", False)

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error during security scan: {e}")
        sys.exit(1)
    finally:
        # Properly shutdown telemetry to flush all pending data
        logger.info("Shutting down telemetry...")

        # Get providers from global registry
        trace_provider = trace.get_tracer_provider()
        meter_provider = metrics.get_meter_provider()

        if trace_provider:
            logger.debug("Flushing traces...")
            trace_provider.force_flush(timeout_millis=30000)
            trace_provider.shutdown()
            logger.debug("✓ Traces flushed")

        if meter_provider:
            logger.debug("Flushing metrics...")
            meter_provider.force_flush(timeout_millis=30000)
            meter_provider.shutdown()
            logger.debug("✓ Metrics flushed")

        if logger_provider:
            logger.debug("Flushing logs...")
            logger_provider.force_flush(timeout_millis=30000)
            logger_provider.shutdown()
            logger.debug("✓ Logs flushed")

        logger.info("✓ Telemetry shutdown complete")


if __name__ == "__main__":
    main()
