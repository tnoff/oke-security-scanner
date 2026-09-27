"""Secret-age tracker — sibling package to the OKE security scanner.

Reports on secrets ≥90 days old across the three storage layers
(terraform-admin tfvars via the layer-1 ledger ConfigMap,
terraform-managed k8s Secrets via OCI IAM time_created + annotation
override, SealedSecrets in docker-apps via GitLab file blame).

Lives alongside the scanner in this repo per
docs/projects/secret-age-tracker.md, but ships as its own package/image
(docs/projects/oke-security-scanner-package-split.md) — no Trivy, no OCIR
cleanup code, no OpenTelemetry. Shares the scanner's OCI auth mounts and
Discord webhook secret at the k8s manifest level, not the image.
Invoked as `python -m secret_age`.
"""
