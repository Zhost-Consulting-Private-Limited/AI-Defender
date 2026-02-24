import json
from sqlmodel import Session, select
from .models import Event, RiskScore, Incident, Agent, Command


def calculate_risk(event_type: str, severity: str) -> tuple[float, float, str]:
    base = {"low": 20, "medium": 50, "high": 80, "critical": 95}.get(severity, 10)
    if event_type in {"mass_rename", "ransomware_signal", "privilege_escalation"}:
        base += 10
    score = min(100.0, float(base))
    insider = min(100.0, score * 0.8)
    return score, insider, f"{event_type} detected with {severity} severity"


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
                mitre_technique="T1078",
                severity=e["severity"],
            )
            session.add(incident)
            created.append(incident)
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
