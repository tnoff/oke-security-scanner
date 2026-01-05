"""Main entry point for OKE Security Scanner."""

import sys
import time
import logging
from logging import getLogger

from opentelemetry.sdk._logs import LoggingHandler

from .config import Config
from .telemetry import setup_telemetry, create_metrics
from .k8s_client import KubernetesClient
from .scanner import TrivyScanner
from .discord_notifier import DiscordNotifier
from .registry_client import RegistryClient
from .version_reporter import VersionReporter, CleanupReporter


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

    # Initialize providers as None so they're accessible in finally block
    trace_provider = None
    meter_provider = None
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
        trace_provider, meter_provider, logger_provider = setup_telemetry(config)

        # Add OTLP logging handler if logs are enabled
        if logger_provider:
            logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

        # Create metrics (returns None if meter_provider is None)
        scanner_metrics = create_metrics(meter_provider)
        logger.info(f"✓ OpenTelemetry initialized (endpoint: {config.otlp_endpoint})")

        # Start root trace span (if tracing enabled)
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
        images = k8s_client.get_all_images()
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

        # Check for version updates
        logger.info("-" * 60)
        logger.info("Checking for image version updates...")
        logger.info("-" * 60)

        registry_client = RegistryClient(config)
        update_results = []

        for idx, image in enumerate(sorted(images), 1):
            logger.debug(f"[{idx}/{len(images)}] Checking updates for: {image}")
            update_info = registry_client.check_for_updates(image)

            if update_info:
                update_results.append({
                    "image": image,
                    "update_info": update_info,
                })
                logger.info(f"  └─ Update available: {image}")

        # Generate and display version update report
        if update_results:
            report = VersionReporter.generate_report(update_results)
            print(report)
            VersionReporter.log_summary(update_results)
        else:
            logger.info("✓ All images are up to date")

        # Check for cleanup recommendations (OCIR only)
        logger.info("-" * 60)
        logger.info("Checking for OCIR cleanup recommendations...")
        logger.info("-" * 60)

        cleanup_recommendations = registry_client.get_cleanup_recommendations(
            images, keep_count=config.ocir_cleanup_keep_count
        )

        # Generate and display cleanup report
        if cleanup_recommendations:
            cleanup_report = CleanupReporter.generate_report(cleanup_recommendations)
            print(cleanup_report)
            CleanupReporter.log_summary(cleanup_recommendations)

            # Delete old images if cleanup is enabled
            if config.ocir_cleanup_enabled:
                logger.info("-" * 60)
                logger.info("OCIR cleanup enabled - deleting old images...")
                logger.info("-" * 60)

                deletion_results = registry_client.delete_ocir_images(cleanup_recommendations)

                # Log deletion summary
                total_deleted = sum(r['total_deleted'] for r in deletion_results.values())
                total_failed = sum(r['total_failed'] for r in deletion_results.values())

                logger.info(f"Deletion complete: {total_deleted} images deleted, {total_failed} failed")

                if total_failed > 0:
                    logger.warning("Some deletions failed - check logs for details")
            else:
                logger.info("OCIR cleanup disabled - no images will be deleted")
                logger.info("Set OCIR_CLEANUP_ENABLED=true to enable automatic deletion")
        else:
            logger.info("✓ No cleanup recommendations")

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
        logger.info(f"  Updates available:     {len(update_results)}")
        logger.info("=" * 60)

        # Report critical vulnerabilities but don't fail the job
        if total_critical > 0:
            logger.warning("⚠ CRITICAL VULNERABILITIES DETECTED!")
            logger.warning(f"  Found {total_critical} critical vulnerabilities")
            logger.warning("  Review the scan results above for details")
        else:
            logger.info("✓ No critical vulnerabilities found - scan passed")

        # Send Discord webhook notification if configured
        if config.discord_webhook_url:
            try:
                logger.debug("Sending Discord webhook notification...")
                notifier = DiscordNotifier(config.discord_webhook_url)
                notifier.send_scan_report(
                    scan_results=scan_results,
                    total_critical=total_critical,
                    total_high=total_high,
                    duration=total_duration,
                    total_images=len(images),
                    update_results=update_results,
                    cleanup_recommendations=cleanup_recommendations,
                )
                logger.info("✓ Discord scan report sent")

                # Send cleanup recommendations as a separate message
                if cleanup_recommendations:
                    notifier.send_cleanup_recommendations(cleanup_recommendations)
                    logger.info("✓ Discord cleanup recommendations sent")
            except Exception as e:
                # Webhook failure doesn't fail the scan
                logger.warning(f"Failed to send Discord notification: {e}")
        else:
            logger.debug("Discord webhook not configured, skipping notification")

        logger.info("Scan completed successfully")

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error during security scan: {e}")
        sys.exit(1)
    finally:
        # Properly shutdown telemetry to flush all pending data
        logger.info("Shutting down telemetry...")

        # Use providers from setup_telemetry (will be None if disabled)
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
