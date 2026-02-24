# Architecture Blueprint

## 1. High-Level Distributed Architecture

```text
+--------------------------- Enterprise Endpoints ----------------------------+
|                                                                            |
|  +--------------------+   +--------------------+   +--------------------+  |
|  | Windows Agent      |   | macOS Agent        |   | Linux Agent        |  |
|  | ETW/WMI/Registry   |   | ESF/FSEvents       |   | auditd/eBPF/inotify|  |
|  | Local Rules Engine |   | Local Rules Engine |   | Local Rules Engine |  |
|  | Event Buffer       |   | Event Buffer       |   | Event Buffer       |  |
|  +---------+----------+   +---------+----------+   +---------+----------+  |
|            | mTLS + cert pinning              |                        |
+------------+----------------------------------+------------------------+
             |                                  |
      +------+----------------------------------+------+
      |        Ingestion/API Gateway (FastAPI)         |
      | RBAC, AuthN/AuthZ, Rate Limiting, Audit Trail  |
      +---------------------+---------------------------+
                            |
                 +----------+----------+
                 | Kafka Event Bus      |
                 +----------+----------+
                            |
     +----------------------+----------------------+-------------------+
     |                      |                      |                   |
+----v-----+          +-----v------+         +-----v-----+      +-----v-----+
| UEBA     |          | Threat Corr|         | DLP Engine|      | FIM Engine |
| Engine   |          | + MITRE    |         | Policies  |      | Hash/Rules |
+----+-----+          +-----+------+         +-----+-----+      +-----+-----+
     |                      |                      |                   |
     +----------------------+----------------------+-------------------+
                            |
                     +------v------------------------------+
                     | Risk Scoring + Explainability Layer |
                     +------+------------------------------+
                            |
           +----------------+----------------+
           |                                 |
   +-------v--------+                 +------v-------+
   | PostgreSQL     |                 | Elasticsearch |
   | Config, Scores |                 | Search/Logs   |
   +-------+--------+                 +------+--------+
           |                                 |
           +----------------+----------------+
                            |
                 +----------v----------+
                 | SOC Dashboard       |
                 | Heatmaps/Timeline   |
                 | Compliance Views    |
                 +----------+----------+
                            |
                 +----------v----------+
                 | Integrations Layer  |
                 | SIEM/SOAR/AD/Okta   |
                 +---------------------+
```

## 2. Core Services

1. **Endpoint Agent (Go/Rust)**
   - Background daemon with low-overhead collectors and local risk heuristics.
   - Tamper resistance via signed config and binary integrity checks.
   - Offline store-and-forward queue with exponential backoff.
2. **Control Plane (FastAPI)**
   - Tenant management, RBAC, policy distribution, certificate lifecycle.
3. **Streaming/Data Plane**
   - Kafka for event streaming, Redis for low-latency cache, PostgreSQL for system-of-record, Elasticsearch for analytics.
4. **Analytics Plane**
   - Baseline learning (14–30 days), anomaly models, graph correlation, insider risk index.
5. **Operations Plane**
   - SOC dashboards, hourly intelligence reports, compliance dashboards, incident workflow.

## 3. Multi-Tenancy and Isolation

- Tenant-scoped keys and row-level security in PostgreSQL.
- Separate Elasticsearch index namespaces per tenant.
- Per-tenant encryption envelope keys (KMS-backed).
- Policy and model deployment ring-fencing by tenant.

## 4. Zero Trust Mapping

- Mutual TLS for every agent↔platform and service↔service connection.
- Continuous authentication with short-lived certs and token rotation.
- Least privilege RBAC/ABAC controls with audit logging.
- Device trust included in session risk calculations.

## 5. Hourly Security Intelligence Pipeline

1. Aggregate events and anomaly deltas.
2. Recompute user, endpoint, and org risk slices.
3. Map incidents to MITRE ATT&CK techniques.
4. Generate actions and playbook links.
5. Dispatch via dashboard, email, SIEM, webhook.

## 6. Scalability Targets

- 1M+ events/min ingestion capacity using horizontally scaled Kafka consumers.
- <2 second P95 event-to-dashboard latency.
- 99.9% availability with multi-AZ stateful services.

## 7. Recommended Repository Service Topology

- `agent/` endpoint binaries and update verifier.
- `platform/api` FastAPI APIs.
- `platform/analytics` model training/inference jobs.
- `platform/reporting` hourly report scheduler.
- `frontend/` SOC console.
