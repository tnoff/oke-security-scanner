"""Secret-age tracker — sibling package to the OKE security scanner.

Reports on secrets ≥90 days old across the three storage layers
(terraform-admin tfvars via the layer-1 ledger ConfigMap,
terraform-managed k8s Secrets via OCI IAM time_created + annotation
override, SealedSecrets in docker-apps via GitLab file blame).

Folded into this repo per docs/projects/secret-age-tracker.md;
shares the scanner's image, OCI auth, and Discord webhook.
Invoked as `python -m src.secret_age`.
"""
