"""Trivy scanner wrapper for vulnerability scanning."""

from logging import getLogger

import json
import subprocess
import time
from typing import Optional

from opentelemetry.sdk._logs import LoggingHandler
from opentelemetry import trace

from .config import Config

tracer = trace.get_tracer(__name__)
logger = getLogger(__name__)

class TrivyScanner:
    """Wrapper for Trivy vulnerability scanner."""

    def __init__(self, cfg: Config, metrics: dict, logger_provider):
        """Initialize Trivy scanner."""
        self.cfg = cfg
        self.metrics = metrics
        self.db_updated = False
        logger.addHandler(LoggingHandler(level=10, logger_provider=logger_provider))

    def update_database(self) -> bool:
        """Update Trivy vulnerability database."""
        with tracer.start_as_current_span("update-trivy-db") as span:
            try:
                logger.info("Updating Trivy vulnerability database")
                start_time = time.time()

                subprocess.run(
                    ["trivy", "image", "--download-db-only"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=True,
                )

                duration = time.time() - start_time
                logger.info(
                    "Trivy database updated successfully",
                    duration_seconds=round(duration, 2),
                )

                span.set_attribute("trivy.db_update.success", True)
                span.set_attribute("trivy.db_update.duration", duration)

                self.db_updated = True
                return True

            except subprocess.TimeoutExpired:
                logger.warning("Trivy database update timed out, using cached database")
                span.set_attribute("trivy.db_update.success", False)
                span.set_attribute("trivy.db_update.error", "timeout")
                return False

            except subprocess.CalledProcessError as e:
                logger.warning(
                    "Trivy database update failed, using cached database",
                    error=e.stderr,
                )
                span.set_attribute("trivy.db_update.success", False)
                span.set_attribute("trivy.db_update.error", e.stderr)
                return False

    def scan_image(self, image: str) -> Optional[dict]:
        """Scan a container image for vulnerabilities."""
        with tracer.start_as_current_span("scan-image") as span:
            span.set_attribute("image.name", image)
            start_time = time.time()

            try:
                logger.info("Scanning image", image=image)

                # Run Trivy scan
                result = subprocess.run(
                    [
                        "trivy",
                        "image",
                        "--format", "json",
                        "--severity", self.cfg.trivy_severity,
                        "--timeout", str(self.cfg.trivy_timeout),
                        "--quiet",
                        image,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.cfg.trivy_timeout + 30,
                    check=True,
                )

                duration = time.time() - start_time

                # Parse results
                scan_results = json.loads(result.stdout)
                vulnerabilities = self._parse_vulnerabilities(scan_results)

                # Log results
                logger.info(
                    "Image scan completed",
                    image=image,
                    duration_seconds=round(duration, 2),
                    critical=vulnerabilities.get("CRITICAL", 0),
                    high=vulnerabilities.get("HIGH", 0),
                )

                # Record metrics - set gauge with image and vulnerability counts
                self.metrics["scan_total"].set(
                    vulnerabilities.get("CRITICAL", 0),
                    {
                        "image": image,
                        "severity": "critical",
                    }
                )
                self.metrics["scan_total"].set(
                    vulnerabilities.get("HIGH", 0),
                    {
                        "image": image,
                        "severity": "high",
                    }
                )

                # Set span attributes
                span.set_attribute("scan.success", True)
                span.set_attribute("scan.duration", duration)
                span.set_attribute("vulnerabilities.critical", vulnerabilities.get("CRITICAL", 0))
                span.set_attribute("vulnerabilities.high", vulnerabilities.get("HIGH", 0))

                return {
                    "image": image,
                    "duration": duration,
                    "vulnerabilities": vulnerabilities,
                    "results": scan_results,
                }

            except subprocess.TimeoutExpired:
                logger.error("Image scan timed out", image=image)
                span.set_attribute("scan.success", False)
                span.set_attribute("scan.error", "timeout")
                return None

            except subprocess.CalledProcessError as e:
                logger.error(
                    "Image scan failed",
                    image=image,
                    error=e.stderr,
                )
                span.set_attribute("scan.success", False)
                span.set_attribute("scan.error", e.stderr)
                return None

            except json.JSONDecodeError as e:
                logger.error(
                    "Failed to parse Trivy output",
                    image=image,
                    error=str(e),
                )
                span.set_attribute("scan.success", False)
                span.set_attribute("scan.error", "parse_error")
                return None

    def _parse_vulnerabilities(self, scan_results: dict) -> dict[str, int]:
        """Parse vulnerability counts by severity from Trivy results."""
        vulnerabilities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        if not scan_results or "Results" not in scan_results:
            return vulnerabilities

        for result in scan_results.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                if severity in vulnerabilities:
                    vulnerabilities[severity] += 1

                    # Log individual critical vulnerabilities
                    if severity == "CRITICAL":
                        logger.warning(
                            "Critical vulnerability found",
                            cve_id=vuln.get("VulnerabilityID"),
                            package=vuln.get("PkgName"),
                            installed_version=vuln.get("InstalledVersion"),
                            fixed_version=vuln.get("FixedVersion"),
                            title=vuln.get("Title", "")[:100],
                        )

        return vulnerabilities
