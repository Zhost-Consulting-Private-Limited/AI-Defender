# Enterprise Behavioral Intelligence & Endpoint Security Platform

This repository ships a working end-to-end implementation:

- FastAPI backend APIs for enrollment, telemetry ingestion, risk scoring, incidents, reports, policy/command control, and audit logs.
- Multi-platform Go endpoint agent (Linux/macOS/Windows collectors, endpoint health, offline event queue + retry, command polling).
- SOC dashboard for operators with hourly report generation.

## Quickstart

### 1) Start API + Dashboard

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open dashboard at `http://127.0.0.1:8000` and use API key `analyst-key`.

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
