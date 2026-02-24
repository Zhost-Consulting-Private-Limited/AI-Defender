from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_end_to_end_flow():
    tenant = client.post('/api/v1/tenants?name=Acme').json()
    tenant_id = tenant['id']

    enroll = client.post('/api/v1/agents/enroll', json={
        'tenant_id': tenant_id,
        'endpoint_id': 'ep-1',
        'hostname': 'host1',
        'os_type': 'linux',
        'agent_version': '2.0.0'
    })
    assert enroll.status_code == 200

    ev = client.post('/api/v1/events', json={
        'tenant_id': tenant_id,
        'endpoint_id': 'ep-1',
        'events': [
            {'event_type': 'privilege_escalation', 'severity': 'high', 'payload': {'x': 1}}
        ]
    })
    assert ev.status_code == 200
    assert ev.json()['incidents_created'] >= 1

    summary = client.get(f'/api/v1/dashboard/summary?tenant_id={tenant_id}')
    assert summary.status_code == 200
    assert summary.json()['open_incidents'] >= 1
