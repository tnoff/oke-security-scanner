"""Main entry point for OKE Security Scanner."""

import sys
import time
from logging import getLogger

from opentelemetry.sdk._logs import LoggingHandler

from .config import Config
from .telemetry import setup_telemetry, create_metrics
from .k8s_client import KubernetesClient
from .scanner import TrivyScanner


logger = getLogger(__name__)

def main():
    """Run the security scanner."""
    trace_provider = None
    meter_provider = None
    logger_provider = None

    try:
        # Load configuration
        config = Config.from_env()
        config.validate()
        logger.info("Configuration loaded successfully")

        # Setup OpenTelemetry
        trace_provider, meter_provider, logger_provider = setup_telemetry()
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))
        metrics = create_metrics(meter_provider)
        logger.info(f"OpenTelemetry initialized (endpoint: {config.otlp_endpoint})")

        # Start root trace span
        with trace_provider.get_tracer(__name__).start_as_current_span("security-scan") as root_span:
            start_time = time.time()

            # Initialize scanner
            scanner = TrivyScanner(config, metrics, logger_provider)

            # Update Trivy database
            db_updated = scanner.update_database()
            root_span.set_attribute("trivy.db_updated", db_updated)

            # Initialize Kubernetes client
            k8s_client = KubernetesClient(config, logger_provider)

            # Get all deployed images
            with trace_provider.start_as_current_span("get-cluster-images") as span:
                images = k8s_client.get_all_images()
                span.set_attribute("images.total", len(images))
                logger.info(f"Discovered {len(images)} images")

            # Scan each image
            scan_results = []
            total_critical = 0
            total_high = 0
            failed_scans = 0

            for image in sorted(images):
                result = scanner.scan_image(image)
                if result:
                    scan_results.append(result)
                    total_critical += result["vulnerabilities"].get("CRITICAL", 0)
                    total_high += result["vulnerabilities"].get("HIGH", 0)
                else:
                    failed_scans += 1

            # Calculate total duration
            total_duration = time.time() - start_time

            # Log summary
            logger.info(
                f"Security scan completed in {round(total_duration, 2)}s: "
                f"{len(scan_results)} scanned, {failed_scans} failed, {len(images)} total, "
                f"{total_critical} critical, {total_high} high"
            )

            # Set root span attributes
            root_span.set_attribute("scan.images.total", len(images))
            root_span.set_attribute("scan.images.scanned", len(scan_results))
            root_span.set_attribute("scan.images.failed", failed_scans)
            root_span.set_attribute("scan.vulnerabilities.critical", total_critical)
            root_span.set_attribute("scan.vulnerabilities.high", total_high)

            # Exit with error if critical vulnerabilities found
            if total_critical > 0:
                logger.error(f"Critical vulnerabilities detected! Count: {total_critical}")
                root_span.set_attribute("scan.has_critical", True)
                sys.exit(1)

            logger.info("No critical vulnerabilities found")
            root_span.set_attribute("scan.has_critical", False)

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error during security scan: {e}")
        sys.exit(1)
    finally:
        # Properly shutdown telemetry to flush all pending data
        if trace_provider:
            logger.info("Flushing traces...")
            trace_provider.force_flush(timeout_millis=30000)
            trace_provider.shutdown()
        if meter_provider:
            logger.info("Flushing metrics...")
            meter_provider.force_flush(timeout_millis=30000)
            meter_provider.shutdown()
        if logger_provider:
            logger.info("Flushing logs...")
            logger_provider.force_flush(timeout_millis=30000)
            logger_provider.shutdown()


if __name__ == "__main__":
    main()
