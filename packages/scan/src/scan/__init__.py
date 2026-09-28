"""Trivy vulnerability scan -- sibling package to secret-age-tracker and
ocir-cleanup, reporting over OTLP.

Split out of the combined scan+cleanup image
(docs/projects/oke-security-scanner-package-split.md): no OCIR cleanup
code. Discovers all images deployed in OKE and scans each with Trivy.
Invoked as `python -m scan`.
"""
