# Enterprise Behavioral Intelligence & Endpoint Security Platform

This repository ships a working end-to-end implementation:

- FastAPI backend APIs for enrollment, telemetry ingestion, risk scoring, incidents, reports, policy/command control, SIEM webhook integration, and audit logs.
- Multi-platform Go endpoint agent in `agent-go/` (Linux/macOS/Windows collectors, endpoint health, offline event queue + retry, command polling).
- SOC dashboard for operators with hourly report generation.
This repository ships a working end-to-end implementation:

- FastAPI backend APIs for enrollment, telemetry ingestion, risk scoring, incidents, reports, policy/command control, and audit logs.
- Multi-platform Go endpoint agent (Linux/macOS/Windows collectors, endpoint health, offline event queue + retry, command polling).
- SOC dashboard for operators with hourly report generation.
This repository now ships a **working end-to-end implementation** (not just blueprint docs):

- FastAPI backend APIs for agent enrollment, telemetry ingestion, policy/command control, risk scoring, incidents, and hourly reporting.
- Multi-platform Go endpoint agent (Linux/macOS/Windows collectors + health telemetry + command polling).
- SOC web dashboard for real-time controls and incident response.
- Supporting architecture/compliance/security docs retained under `docs/`.

## Quickstart

### 1) Start API + Dashboard

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open dashboard at `http://127.0.0.1:8000` and use API key `analyst-key`.
Open dashboard at `http://127.0.0.1:8000`.

### 2) Run Endpoint Agent

```bash
cd agent-go
go run ./cmd/agent --api http://127.0.0.1:8000 --tenant 1 --endpoint endpoint-001
```

### 3) Default API key roles

- `admin-key`
- `analyst-key`
- `agent-key`

Override with env var `API_KEYS="key1:admin,key2:analyst,key3:agent"`.
go mod tidy
go run ./cmd/agent --api http://127.0.0.1:8000 --tenant 1 --endpoint endpoint-001
```

### 3) API highlights

- `POST /api/v1/tenants`
- `POST /api/v1/agents/enroll`
- `POST /api/v1/events`
- `GET /api/v1/dashboard/summary?tenant_id={id}`
- `GET /api/v1/incidents?tenant_id={id}`
- `POST /api/v1/commands`
- `GET /api/v1/agents/{endpoint_id}/commands`
- `POST /api/v1/reports/hourly?tenant_id={id}`
