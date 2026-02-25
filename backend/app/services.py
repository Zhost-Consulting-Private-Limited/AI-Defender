import json

import httpx
from datetime import datetime

from sqlmodel import Session, select

from .models import Agent, AuditLog, Command, Event, HourlyReport, Incident, RiskScore


MITRE_MAP = {
    "privilege_escalation": "T1068",
    "credential_access": "T1555",
    "suspicious_login": "T1078",
    "data_exfiltration": "T1048",
    "windows_privilege_escalation": "T1068",
    "linux_process_chain": "T1059",
    "macos_sensitive_file_access": "T1005",
}


def calculate_risk(event_type: str, severity: str) -> tuple[float, float, str]:
    sev_weight = {"low": 20, "medium": 50, "high": 85}.get(severity.lower(), 35)
    evt_bonus = 15 if event_type in {"privilege_escalation", "credential_access"} else 0
    score = min(100.0, float(sev_weight + evt_bonus))
    insider = round(min(0.99, score / 100.0), 2)
    return score, insider, f"{event_type} detected with {severity} severity"


def add_audit(session: Session, tenant_id: int, actor: str, action: str, resource_type: str, resource_id: str) -> None:
    session.add(
        AuditLog(
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
        )
    )


def process_events(session: Session, tenant_id: int, endpoint_id: str, events: list[dict]):
    created_incidents: list[Incident] = []
    for e in events:
        session.add(
            Event(
                tenant_id=tenant_id,
                endpoint_id=endpoint_id,
                user_id=e.get("user_id"),
                event_type=e["event_type"],
                severity=e["severity"],
                payload=json.dumps(e["payload"]),
            )
        )

        score, insider, reason = calculate_risk(e["event_type"], e["severity"])
        session.add(
            RiskScore(
                tenant_id=tenant_id,
                user_id=e.get("user_id"),
                endpoint_id=endpoint_id,
                score=score,
                insider_probability=insider,
                reason=reason,
            )
        )

        if score >= 80:
            incident = Incident(
                tenant_id=tenant_id,
                endpoint_id=endpoint_id,
                title=f"High risk event: {e['event_type']}",
                mitre_technique=MITRE_MAP.get(e["event_type"], "T1078"),
                severity=e["severity"],
            )
            session.add(incident)
            created_incidents.append(incident)

    agent = session.exec(select(Agent).where(Agent.endpoint_id == endpoint_id)).first()
    if agent:
        agent.last_seen = datetime.utcnow()
        agent.health_score = max(1, 100 - len(created_incidents)*10)
        session.add(agent)

    add_audit(session, tenant_id, "agent", "event_ingest", "endpoint", endpoint_id)
    session.commit()
    return created_incidents


def dequeue_commands(session: Session, endpoint_id: str):
    cmds = session.exec(select(Command).where(Command.endpoint_id == endpoint_id, Command.status == "pending")).all()
    for c in cmds:
        c.status = "delivered"
        session.add(c)
    session.commit()
    return cmds



def build_siem_payload(tenant_id: int, provider: str, incidents: list[Incident]) -> dict:
    normalized_provider = provider.strip().lower()
    records = [
        {
            "id": i.id,
            "endpoint_id": i.endpoint_id,
            "title": i.title,
            "severity": i.severity,
            "mitre_technique": i.mitre_technique,
            "status": i.status,
            "created_at": i.created_at.isoformat(),
        }
        for i in incidents
    ]
    return {
        "provider": normalized_provider,
        "tenant_id": tenant_id,
        "sent_at": datetime.utcnow().isoformat(),
        "incident_count": len(records),
        "incidents": records,
    }


def forward_incidents_to_siem(
    session: Session,
    tenant_id: int,
    provider: str,
    webhook_url: str,
    max_incidents: int = 25,
) -> dict:
    limit = max(1, min(max_incidents, 100))
    incidents = session.exec(
        select(Incident).where(Incident.tenant_id == tenant_id).order_by(Incident.created_at.desc())
    ).all()[:limit]

    payload = build_siem_payload(tenant_id, provider, incidents)
    response = httpx.post(webhook_url, json=payload, timeout=10.0)
    response.raise_for_status()

    add_audit(session, tenant_id, "analyst", "forward_siem", "tenant", str(tenant_id))
    session.commit()

    return {
        "status": "forwarded",
        "provider": provider.strip().lower(),
        "sent": len(incidents),
        "webhook_status": response.status_code,
    }

def create_hourly_report(session: Session, tenant_id: int) -> dict:
    latest_incidents = session.exec(
        select(Incident).where(Incident.tenant_id == tenant_id).order_by(Incident.created_at.desc())
    ).all()[:50]
    mitre = sorted({i.mitre_technique for i in latest_incidents})
    summary = {
        "tenant_id": tenant_id,
        "generated_at": datetime.utcnow().isoformat(),
        "anomalies": len(latest_incidents),
        "mitre_techniques": mitre,
        "recommended_action": "Contain endpoints with critical/high incidents and rotate high-risk credentials.",
    }
    session.add(HourlyReport(tenant_id=tenant_id, summary=json.dumps(summary)))
    add_audit(session, tenant_id, "system", "hourly_report", "tenant", str(tenant_id))
    session.commit()
    return summary
