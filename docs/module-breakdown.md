# Core Module Breakdown

## Endpoint Agent Modules

- `collector.auth`: Login patterns, geolocation changes, failed auth bursts.
- `collector.process`: Process trees, suspicious chains, persistence signatures.
- `collector.file`: Real-time file integrity monitor, mass rename, encryption heuristics.
- `collector.network`: Beaconing cadence and outbound spike detection.
- `collector.system`: CPU/memory/disk anomalies and unauthorized software installation.
- `policy.engine`: Local rule evaluation and policy sync.
- `queue.buffer`: Encrypted offline cache, retry and dedupe.
- `crypto.guard`: Certificate pinning, payload signing, key handling.

## Backend Modules

- `api-gateway`: Authentication, RBAC, tenant scoping, policy APIs.
- `ingestion-service`: Agent enrollment, event validation, Kafka producer.
- `analytics-engine`: Baselines, anomaly models, peer-group scoring, risk aggregation.
- `threat-correlation`: MITRE mapping, graph correlations, threat intel enrichment.
- `reporting-service`: Hourly intelligence report scheduler and exporters.
- `integration-hub`: SIEM/SOAR/ITSM connectors.
- `compliance-service`: Control mapping, evidence export, retention governance.

## SOC Dashboard Modules

- Endpoint posture map
- User risk heatmap
- Incident timeline
- ATT&CK explorer
- Compliance dashboard
