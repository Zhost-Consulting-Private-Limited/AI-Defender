# STRIDE Threat Model

## Scope

- Endpoint agents
- Ingestion APIs
- Streaming pipeline
- Data stores
- Dashboard and integrations

## STRIDE Analysis

| STRIDE | Threat | Example | Mitigation |
|---|---|---|---|
| Spoofing | Rogue agent identity | Attacker registers fake endpoint | mTLS with device-bound certs, TPM-backed key storage, cert rotation |
| Tampering | Event payload manipulation | MITM alters anomalies | TLS 1.3 + payload signatures + hash chain sequence IDs |
| Repudiation | Actor denies risky action | Privilege escalation denied by user | Immutable audit logs, signed event metadata, time sync with NTP |
| Information Disclosure | Sensitive telemetry leakage | Unauthorized analyst sees PII | Data minimization, field-level encryption, role-scoped views |
| Denial of Service | Ingestion overload | Burst event flood | Rate limiting, Kafka buffering, circuit breakers, autoscaling |
| Elevation of Privilege | Admin token abuse | Compromised SOC account | MFA, just-in-time privilege, UEBA on admin actions |

## Critical Assets

- Behavioral telemetry
- Risk scoring models
- Tenant secrets/certs
- Compliance evidence artifacts

## Security Controls

- Signed agent binaries and signed updates.
- Anti-tamper service watchdog.
- WORM storage for audit logs.
- KMS-backed encryption keys and automated rotation.
