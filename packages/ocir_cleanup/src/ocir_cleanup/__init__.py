"""OCIR cleanup sweep -- sibling package to the OKE security scanner.

Split out of the combined scan+cleanup image
(docs/projects/oke-security-scanner-package-split.md): no Trivy binary.
Prunes stale OCIR tags beyond a configurable keep_count and removes
orphaned platform manifests, protecting the deployed tag, `latest`, and
any multi-arch sub-manifest digests referenced by kept tags.
Invoked as `python -m ocir_cleanup`.
"""
