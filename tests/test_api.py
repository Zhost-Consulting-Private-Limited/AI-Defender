import sys
from pathlib import Path
from unittest.mock import Mock, patch

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


def test_siem_forward_webhook():
    init_db()
    with TestClient(app) as client:
        tenant = client.post('/api/v1/tenants?name=Acme-SIEM', headers=ADMIN).json()
        tenant_id = tenant['id']

        client.post('/api/v1/agents/enroll', headers=AGENT, json={
            'tenant_id': tenant_id,
            'endpoint_id': 'ep-siem-1',
            'hostname': 'host-siem',
            'os_type': 'linux',
            'agent_version': '2.2.0'
        })
        client.post('/api/v1/events', headers=AGENT, json={
            'tenant_id': tenant_id,
            'endpoint_id': 'ep-siem-1',
            'events': [
                {'event_type': 'credential_access', 'severity': 'high', 'payload': {'src': 'test'}},
                {'event_type': 'suspicious_login', 'severity': 'medium', 'payload': {'src': 'test'}}
            ]
        })

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()

        with patch('backend.app.services.httpx.post', return_value=mock_response) as mock_post:
            forwarded = client.post('/api/v1/integrations/siem/forward', headers=ANALYST, json={
                'tenant_id': tenant_id,
                'provider': 'splunk',
                'webhook_url': 'https://siem.example.com/webhook',
                'max_incidents': 10
            })

        assert forwarded.status_code == 200
        data = forwarded.json()
        assert data['status'] == 'forwarded'
        assert data['provider'] == 'splunk'
        assert data['sent'] >= 1

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs['json']
        assert payload['tenant_id'] == tenant_id
        assert payload['provider'] == 'splunk'
        assert payload['incident_count'] >= 1


def test_agent_mtls_guardrails():
    init_db()
    with patch.dict('os.environ', {'AGENT_MTLS_REQUIRED': 'true'}, clear=False):
        from backend.app import auth as auth_module

        auth_module.KEY_ROLE_MAP = {'agent-key': 'agent', 'admin-key': 'admin'}

        with TestClient(app) as client:
            tenant = client.post('/api/v1/tenants?name=Acme-mTLS', headers=ADMIN).json()
            tenant_id = tenant['id']

            base_payload = {
                'tenant_id': tenant_id,
                'endpoint_id': 'ep-mtls-1',
                'hostname': 'host-mtls',
                'os_type': 'linux',
                'agent_version': '2.2.0'
            }

            missing = client.post('/api/v1/agents/enroll', headers=AGENT, json=base_payload)
            assert missing.status_code == 401

            untrusted = client.post(
                '/api/v1/agents/enroll',
                headers={
                    **AGENT,
                    'X-Client-Cert-Presented': 'true',
                    'X-Client-Cert-Fingerprint': 'abc123'
                },
                json=base_payload,
            )
            assert untrusted.status_code == 200

    with patch.dict(
        'os.environ',
        {
            'AGENT_MTLS_REQUIRED': 'true',
            'AGENT_MTLS_TRUSTED_FINGERPRINTS': 'trusted-001'
        },
        clear=False,
    ):
        from backend.app import auth as auth_module

        auth_module.KEY_ROLE_MAP = {'agent-key': 'agent', 'admin-key': 'admin'}

        with TestClient(app) as client:
            tenant = client.post('/api/v1/tenants?name=Acme-mTLS-Trusted', headers=ADMIN).json()
            tenant_id = tenant['id']

            base_payload = {
                'tenant_id': tenant_id,
                'endpoint_id': 'ep-mtls-2',
                'hostname': 'host-mtls',
                'os_type': 'linux',
                'agent_version': '2.2.0'
            }

            rejected = client.post(
                '/api/v1/agents/enroll',
                headers={
                    **AGENT,
                    'X-Client-Cert-Presented': 'true',
                    'X-Client-Cert-Fingerprint': 'wrong-one'
                },
                json=base_payload,
            )
            assert rejected.status_code == 401

            accepted = client.post(
                '/api/v1/agents/enroll',
                headers={
                    **AGENT,
                    'X-Client-Cert-Presented': 'true',
                    'X-Client-Cert-Fingerprint': 'trusted-001'
                },
                json=base_payload,
            )
            assert accepted.status_code == 200
