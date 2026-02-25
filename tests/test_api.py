import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

from backend.app.db import init_db
from backend.app.main import app

ADMIN = {"X-API-Key": "admin-key"}
AGENT = {"X-API-Key": "agent-key"}
ANALYST = {"X-API-Key": "analyst-key"}


def test_end_to_end_flow():
    init_db()
    with TestClient(app) as client:
        tenant = client.post('/api/v1/tenants?name=Acme', headers=ADMIN).json()
        tenant_id = tenant['id']

        enroll = client.post('/api/v1/agents/enroll', headers=AGENT, json={
            'tenant_id': tenant_id,
            'endpoint_id': 'ep-1',
            'hostname': 'host1',
            'os_type': 'linux',
            'agent_version': '2.2.0'
        })
        assert enroll.status_code == 200

        ev = client.post('/api/v1/events', headers=AGENT, json={
            'tenant_id': tenant_id,
            'endpoint_id': 'ep-1',
            'events': [
                {'event_type': 'privilege_escalation', 'severity': 'high', 'payload': {'x': 1}}
            ]
        })
        assert ev.status_code == 200
        assert ev.json()['incidents_created'] >= 1

        summary = client.get(f'/api/v1/dashboard/summary?tenant_id={tenant_id}', headers=ANALYST)
        assert summary.status_code == 200
        assert summary.json()['open_incidents'] >= 1

        report = client.post(f'/api/v1/reports/hourly?tenant_id={tenant_id}', headers=ANALYST)
        assert report.status_code == 200
        assert 'mitre_techniques' in report.json()
