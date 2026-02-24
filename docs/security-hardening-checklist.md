# Security Hardening Checklist

## Platform

- [ ] Enforce TLS 1.3 and mTLS across all service boundaries.
- [ ] Enable cert pinning in endpoint agents.
- [ ] Enforce MFA for dashboard and admin API access.
- [ ] RBAC with least privilege roles and just-in-time elevation.
- [ ] Immutable audit logs to WORM-compatible storage.
- [ ] AES-256 encryption at rest for databases and object storage.
- [ ] KMS/HSM-backed key management with rotation.
- [ ] Runtime security policies for Kubernetes workloads.

## Agent

- [ ] Binary signing and signature verification on startup.
- [ ] Signed update package verification.
- [ ] Anti-tamper watchdog and service restart protection.
- [ ] Local queue encryption and integrity checks.
- [ ] Config signature validation before applying policy updates.

## Operations

- [ ] Vulnerability scanning in CI/CD.
- [ ] SAST/DAST and dependency SBOM generation.
- [ ] Incident runbooks tested quarterly.
- [ ] Backup/restore tests for critical stores.
- [ ] Log retention and legal hold policy controls.
