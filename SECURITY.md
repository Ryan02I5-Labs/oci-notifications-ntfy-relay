# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/Ryan02I5-Labs/oci-notifications-ntfy-relay/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

You can expect an acknowledgement within 7 days. Once a fix is available it is
published as a new release, and the advisory is disclosed after that release.

## Verifying release images

Every release image is built by `.github/workflows/release.yml` on
GitHub-hosted runners and carries a build provenance attestation:

```bash
gh attestation verify oci://ghcr.io/ryan02i5-labs/oci-notifications-ntfy-relay@<digest> \
  --repo Ryan02I5-Labs/oci-notifications-ntfy-relay \
  --signer-workflow Ryan02I5-Labs/oci-notifications-ntfy-relay/.github/workflows/release.yml \
  --source-ref refs/tags/<tag> \
  --deny-self-hosted-runners
```
