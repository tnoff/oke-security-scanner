"""Trivy scanner wrapper for vulnerability scanning."""

import base64
from pathlib import Path
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

        # Authenticate to OCIR for private image access
        self._configure_registry_auth()

    def _configure_registry_auth(self) -> None:
        """Configure Docker registry authentication for private images."""
        if not self.cfg.oci_registry or not self.cfg.oci_username or not self.cfg.oci_token:
            logger.warning("OCIR credentials not fully configured, private image scans may fail")
            return

        try:
            logger.info(f"Authenticating to OCIR registry: {self.cfg.oci_registry}")

            # Create Docker config directory
            docker_config_dir = Path.home() / ".docker"
            docker_config_dir.mkdir(exist_ok=True)

            # OCIR requires username format: <namespace>/<username>
            ocir_username = f"{self.cfg.oci_namespace}/{self.cfg.oci_username}"

            # Create auth token (base64 encode username:password)
            auth_string = f"{ocir_username}:{self.cfg.oci_token}"
            auth_token = base64.b64encode(auth_string.encode()).decode()

            # Create Docker config.json
            # Trivy respects Docker's credential store
            config_content = {
                "auths": {
                    self.cfg.oci_registry: {
                        "auth": auth_token
                    }
                }
            }

            config_file = docker_config_dir / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_content, f, indent=2)

            logger.info("Successfully authenticated to OCIR")

        except Exception as e:
            logger.warning(f"Unexpected error during OCIR authentication: {e}")

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
                logger.info(f"Trivy database updated successfully (duration: {round(duration, 2)}s)")

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
                logger.warning(f"Trivy database update failed, using cached database: {e.stderr}")
                span.set_attribute("trivy.db_update.success", False)
                span.set_attribute("trivy.db_update.error", e.stderr)
                return False

    def scan_image(self, image: str) -> Optional[dict]:
        """Scan a container image for vulnerabilities."""
        with tracer.start_as_current_span("scan-image") as span:
            span.set_attribute("image.name", image)
            start_time = time.time()

            try:
                logger.info(f"Scanning image: {image}")

                # Run Trivy scan
                result = subprocess.run(
                    [
                        "trivy",
                        "image",
                        "--format", "json",
                        "--severity", self.cfg.trivy_severity,
                        "--timeout", f"{self.cfg.trivy_timeout}s",
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
                parsed_vulns = self._parse_vulnerabilities(scan_results)
                vuln_counts = parsed_vulns["counts"]
                vuln_cves = parsed_vulns["cves"]

                # Log results
                logger.info(
                    f"Image scan completed: {image} "
                    f"(duration: {round(duration, 2)}s, "
                    f"critical: {vuln_counts.get('CRITICAL', 0)}, "
                    f"high: {vuln_counts.get('HIGH', 0)})"
                )

                # Record metrics - set gauge with image and vulnerability counts
                self.metrics["scan_total"].set(
                    vuln_counts.get("CRITICAL", 0),
                    {
                        "image": image,
                        "severity": "critical",
                    }
                )
                self.metrics["scan_total"].set(
                    vuln_counts.get("HIGH", 0),
                    {
                        "image": image,
                        "severity": "high",
                    }
                )

                # Set span attributes
                span.set_attribute("scan.success", True)
                span.set_attribute("scan.duration", duration)
                span.set_attribute("vulnerabilities.critical", vuln_counts.get("CRITICAL", 0))
                span.set_attribute("vulnerabilities.high", vuln_counts.get("HIGH", 0))

                return {
                    "image": image,
                    "duration": duration,
                    "vulnerabilities": vuln_counts,
                    "cves": vuln_cves,
                    "results": scan_results,
                }

            except subprocess.TimeoutExpired:
                logger.error(f"Image scan timed out: {image}")
                span.set_attribute("scan.success", False)
                span.set_attribute("scan.error", "timeout")
                return None

            except subprocess.CalledProcessError as e:
                logger.error(f"Image scan failed: {image} - {e.stderr}")
                span.set_attribute("scan.success", False)
                span.set_attribute("scan.error", e.stderr)
                return None

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy output for {image}: {e}")
                span.set_attribute("scan.success", False)
                span.set_attribute("scan.error", "parse_error")
                return None

    def _parse_vulnerabilities(self, scan_results: dict) -> dict:
        """Parse vulnerability counts and CVE details from Trivy results.

        Returns:
            Dictionary with 'counts' and 'cves' keys
        """
        vulnerabilities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cve_details = {}

        if not scan_results or "Results" not in scan_results:
            return {"counts": vulnerabilities, "cves": cve_details}

        for result in scan_results.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                cve_id = vuln.get("VulnerabilityID")

                if severity in vulnerabilities:
                    vulnerabilities[severity] += 1

                    # Store CVE details for webhook reporting
                    if cve_id:
                        cve_details[cve_id] = {
                            "severity": severity,
                            "title": vuln.get("Title", ""),
                            "package": vuln.get("PkgName", ""),
                            "installed": vuln.get("InstalledVersion", ""),
                            "fixed": vuln.get("FixedVersion", ""),
                        }

                    # Log individual critical/high vulnerabilities
                    if severity in ["CRITICAL", "HIGH"]:
                        logger.warning(
                            f"{severity} vulnerability found: {cve_id} in "
                            f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} "
                            f"(fixed: {vuln.get('FixedVersion')}) - {vuln.get('Title', '')[:100]}"
                        )

        return {"counts": vulnerabilities, "cves": cve_details}
