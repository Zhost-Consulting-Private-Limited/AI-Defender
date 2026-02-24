# Features Tracker

This file is the source of truth for feature delivery status.

- ✅ **Done** = implemented in repository
- 🔄 **In Progress** = partially implemented
- ⏳ **To Do** = not yet implemented / production-hardening pending

Last updated: 2026-02-25

---

## 1) Endpoint Agent

- ✅ Cross-platform Go agent runtime loop (Linux/macOS/Windows code paths).
- ✅ Agent enrollment API integration.
- ✅ Telemetry submission pipeline from agent to backend.
- ✅ Local offline file-backed queue and retry drain.
- ✅ Command polling from backend.
- 🔄 Platform-native deep collectors (ETW/WMI, macOS ESF, auditd/eBPF) are currently stub/sample-level.
- ⏳ Tamper resistance hardening.
- ⏳ Signed updates and signature verification chain.
- ⏳ Certificate pinning + mTLS client cert lifecycle.
- ⏳ CPU/RAM optimization validation target (<3%).

## 2) Backend API / Control Plane

- ✅ FastAPI service with tenant, enrollment, events, incidents, commands, policies, reports, audit endpoints.
- ✅ RBAC enforcement via API key role mapping (`admin`, `analyst`, `agent`).
- ✅ SQLModel persistence layer with core tables.
- ✅ Audit log persistence model and write hooks.
- ✅ Hourly report generation endpoint + storage model.
- ✅ OpenAPI contract aligned to implemented `/api/v1/*` API and API-key security model.
- ⏳ Production-grade auth (OIDC/SAML/SCIM, MFA flows).
- ⏳ Multi-tenant hard isolation controls (RLS, schema/db isolation options).
- ⏳ Idempotency, pagination, rate limiting, and API versioning hardening.
- ⏳ HA database + migration framework (Alembic) rollout.

## 3) Behavioral Analytics / UEBA

- ✅ Basic risk scoring pipeline.
- ✅ Basic incident creation for high-risk events.
- ✅ Basic MITRE mapping for selected event types.
- 🔄 Heuristic scoring only (not full ML pipeline).
- ⏳ 14–30 day adaptive baseline learning.
- ⏳ Peer-group modeling and role-based profiling.
- ⏳ Insider threat probability model (advanced).
- ⏳ Drift detection + continuous retraining pipelines.
- ⏳ Explainability outputs (SHAP/LIME integration).

## 4) File Integrity / DLP / Endpoint Health

- ✅ Foundational event model path present in docs/samples.
- 🔄 Health telemetry exists (synthetic/randomized sample currently).
- ⏳ Real-time FIM for critical files with SHA-256 verification pipeline in main agent.
- ⏳ Ransomware behavior detection pipeline.
- ⏳ USB/external media activity monitoring.
- ⏳ Large outbound transfer and suspicious archive detection.
- ⏳ Registry/persistence detection coverage (Windows/macOS/Linux parity).

## 5) SOC Dashboard

- ✅ Basic dashboard UI with KPI summary, incidents, close action, report trigger.
- ✅ API key input and periodic refresh.
- 🔄 Minimal UI/UX; enterprise SOC workflows incomplete.
- ⏳ Real-time streaming updates (websocket/event bus).
- ⏳ MITRE ATT&CK navigator visualization.
- ⏳ Compliance dashboard and evidence export UX.
- ⏳ Role-based UI feature gating and full audit views.

## 6) Security Hardening

- ✅ Basic RBAC and audit trails in application layer.
- 🔄 Security hardening checklist docs provided.
- ⏳ TLS 1.3 + mTLS everywhere in runtime deployment.
- ⏳ Immutable/WORM audit log backend.
- ⏳ Secrets/KMS integration and key rotation.
- ⏳ Signed binaries and secure boot validations where supported.

## 7) Integrations

- 🔄 API foundation supports integration extension.
- ⏳ Active Directory / Azure AD / Okta integration.
- 🔄 SIEM webhook connector prototype implemented (generic webhook target).
- ⏳ Vendor-specific SIEM connectors (Splunk/Sentinel/QRadar).
- ⏳ SOAR integrations.
- ⏳ Jira / ServiceNow incident workflows.
- ⏳ Threat intelligence feed ingestion.

## 8) Compliance / Governance

- ✅ Compliance mapping documentation exists (SOC2/ISO27001/HIPAA/GDPR/PCI references).
- ✅ SOC playbook docs exist.
- 🔄 Operational evidence export is partially modeled (audit/report tables) but not complete.
- ⏳ Retention policies + legal hold tooling.
- ⏳ Full control-evidence export workflows.
- ⏳ Compliance gap reporting automation.

## 9) DevOps / Deployment

- ✅ Kubernetes/Helm/Terraform scaffolding exists.
- 🔄 Deployment artifacts are starter templates, not hardened production stack.
- ⏳ CI/CD with security gates (SAST/DAST/SBOM/signing).
- ⏳ Observability stack (metrics, tracing, alerting) production setup.
- ⏳ Blue/green or canary release strategies.

---

## Immediate Next Priorities (Execution Queue)

1. Replace synthetic health signals with real system metrics collectors.
2. Add migration tooling + production DB configuration.
3. Add mTLS foundation for agent-server trust bootstrap.
4. Expand dashboard with ATT&CK + compliance panes.
5. Add vendor-specific SIEM connectors (Splunk/Sentinel/QRadar).

---

## Change Log

- 2026-02-24: Initialized tracker with current implementation status and next priorities.
- 2026-02-25: Marked OpenAPI alignment as complete and SIEM webhook connector prototype as in progress.
