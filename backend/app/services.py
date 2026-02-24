import json
from datetime import datetime
from sqlmodel import Session, select
from .models import Event, RiskScore, Incident, Agent, Command, HourlyReport, AuditLog

MITRE_MAP = {
    "privilege_escalation": "T1078",
    "mass_rename": "T1486",
    "ransomware_signal": "T1486",
    "linux_process_chain": "T1059",
    "windows_privilege_escalation": "T1078",
    "macos_sensitive_file_access": "T1005",
}
from sqlmodel import Session, select
from .models import Event, RiskScore, Incident, Agent, Command


def calculate_risk(event_type: str, severity: str) -> tuple[float, float, str]:
    base = {"low": 20, "medium": 50, "high": 80, "critical": 95}.get(severity, 10)
    if event_type in {"mass_rename", "ransomware_signal", "privilege_escalation"}:
        base += 10
    score = min(100.0, float(base))
    insider = min(100.0, score * 0.8)
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
    created = []
    for e in events:
        record = Event(
            tenant_id=tenant_id,
            endpoint_id=endpoint_id,
            user_id=e.get("user_id"),
            event_type=e["event_type"],
            severity=e["severity"],
            payload=json.dumps(e["payload"]),
        )
        session.add(record)
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
        rs = RiskScore(
            tenant_id=tenant_id,
            user_id=e.get("user_id"),
            endpoint_id=endpoint_id,
            score=score,
            insider_probability=insider,
            reason=reason,
        )
        session.add(rs)
        if score >= 80:
            incident = Incident(
                tenant_id=tenant_id,
                endpoint_id=endpoint_id,
                title=f"High risk event: {e['event_type']}",
                mitre_technique=MITRE_MAP.get(e["event_type"], "T1078"),
                mitre_technique="T1078",
                severity=e["severity"],
            )
            session.add(incident)
            created.append(incident)

    agent = session.exec(select(Agent).where(Agent.endpoint_id == endpoint_id)).first()
    if agent:
        agent.last_seen = datetime.utcnow()
        agent.health_score = max(1, 100 - len(created) * 10)
        session.add(agent)

    add_audit(session, tenant_id, "agent", "event_ingest", "endpoint", endpoint_id)
    agent = session.exec(select(Agent).where(Agent.endpoint_id == endpoint_id)).first()
    if agent:
        agent.last_seen = agent.last_seen.utcnow()
        agent.health_score = max(1, 100 - len(created) * 10)
        session.add(agent)
    session.commit()
    return created


def dequeue_commands(session: Session, endpoint_id: str):
    cmds = session.exec(select(Command).where(Command.endpoint_id == endpoint_id, Command.status == "pending")).all()
    for c in cmds:
        c.status = "delivered"
        session.add(c)
    session.commit()
    return cmds


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
