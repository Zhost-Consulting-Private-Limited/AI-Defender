from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .auth import require_role
from .db import init_db, get_session
from .models import Tenant, Agent, RiskScore, Incident, Policy, Command, AuditLog, HourlyReport
from .schemas import AgentEnrollRequest, EventBatch, PolicyInput, CommandInput
from .services import process_events, dequeue_commands, create_hourly_report, add_audit

app = FastAPI(title="Behavioral Security Platform API", version="2.1.0")
templates = Jinja2Templates(directory="backend/app/templates")
app.mount("/static", StaticFiles(directory="backend/app/static"), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.post("/api/v1/tenants", dependencies=[Depends(require_role("admin"))])
def create_tenant(name: str, session: Session = Depends(get_session)):
    t = Tenant(name=name)
    session.add(t)
    session.commit()
    session.refresh(t)
    add_audit(session, t.id or 0, "admin", "create_tenant", "tenant", str(t.id))
    session.commit()
    return t


@app.post("/api/v1/agents/enroll", dependencies=[Depends(require_role("agent", "admin"))])
def enroll_agent(payload: AgentEnrollRequest, session: Session = Depends(get_session)):
    agent = session.exec(select(Agent).where(Agent.endpoint_id == payload.endpoint_id)).first()
    if agent:
        agent.last_seen = datetime.utcnow()
        agent.agent_version = payload.agent_version
    else:
        agent = Agent(**payload.model_dump())
    session.add(agent)
    add_audit(session, payload.tenant_id, "agent", "enroll", "endpoint", payload.endpoint_id)
    session.commit()
    session.refresh(agent)
    return {"status": "enrolled", "agent": agent}


@app.post("/api/v1/events", dependencies=[Depends(require_role("agent", "admin"))])
def ingest_events(batch: EventBatch, session: Session = Depends(get_session)):
    incidents = process_events(session, batch.tenant_id, batch.endpoint_id, [e.model_dump() for e in batch.events])
    return {"status": "accepted", "incidents_created": len(incidents)}


@app.get("/api/v1/agents/{endpoint_id}/commands", dependencies=[Depends(require_role("agent", "admin"))])
def poll_commands(endpoint_id: str, session: Session = Depends(get_session)):
    cmds = dequeue_commands(session, endpoint_id)
    return [{"id": c.id, "action": c.action, "status": c.status} for c in cmds]


@app.post("/api/v1/commands", dependencies=[Depends(require_role("analyst", "admin"))])
def create_command(cmd: CommandInput, session: Session = Depends(get_session)):
    c = Command(**cmd.model_dump())
    session.add(c)
    add_audit(session, cmd.tenant_id, "analyst", "create_command", "endpoint", cmd.endpoint_id)
    session.commit()
    session.refresh(c)
    return c


@app.post("/api/v1/policies", dependencies=[Depends(require_role("admin"))])
def create_policy(payload: PolicyInput, session: Session = Depends(get_session)):
    p = Policy(tenant_id=payload.tenant_id, name=payload.name, enabled=payload.enabled, definition=str(payload.definition))
    session.add(p)
    add_audit(session, payload.tenant_id, "admin", "create_policy", "policy", payload.name)
    session.commit()
    session.refresh(p)
    return p


@app.get("/api/v1/dashboard/summary", dependencies=[Depends(require_role("analyst", "admin"))])
def summary(tenant_id: int, session: Session = Depends(get_session)):
    agents = session.exec(select(Agent).where(Agent.tenant_id == tenant_id)).all()
    open_incidents = session.exec(select(Incident).where(Incident.tenant_id == tenant_id, Incident.status == "open")).all()
    risk = session.exec(select(RiskScore).where(RiskScore.tenant_id == tenant_id).order_by(RiskScore.created_at.desc())).all()
    return {
        "agent_count": len(agents),
        "open_incidents": len(open_incidents),
        "avg_risk": round(sum(r.score for r in risk[:50]) / max(1, len(risk[:50])), 2),
        "top_risks": [
            {"endpoint_id": r.endpoint_id, "score": r.score, "reason": r.reason, "at": r.created_at.isoformat()}
            for r in risk[:10]
        ],
    }


@app.post("/api/v1/reports/hourly", dependencies=[Depends(require_role("analyst", "admin"))])
def hourly_report(tenant_id: int, session: Session = Depends(get_session)):
    return create_hourly_report(session, tenant_id)


@app.get("/api/v1/reports", dependencies=[Depends(require_role("analyst", "admin"))])
def list_reports(tenant_id: int, session: Session = Depends(get_session)):
    reports = session.exec(select(HourlyReport).where(HourlyReport.tenant_id == tenant_id).order_by(HourlyReport.generated_at.desc())).all()
    return reports[:50]


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/v1/incidents", dependencies=[Depends(require_role("analyst", "admin"))])
def list_incidents(tenant_id: int, session: Session = Depends(get_session)):
    return session.exec(select(Incident).where(Incident.tenant_id == tenant_id).order_by(Incident.created_at.desc())).all()


@app.patch("/api/v1/incidents/{incident_id}/status", dependencies=[Depends(require_role("analyst", "admin"))])
def update_incident_status(incident_id: int, status: str, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")
    incident.status = status
    session.add(incident)
    add_audit(session, incident.tenant_id, "analyst", "update_incident", "incident", str(incident_id))
    session.commit()
    return {"ok": True}


@app.get("/api/v1/audit", dependencies=[Depends(require_role("admin"))])
def audit_logs(tenant_id: int, session: Session = Depends(get_session)):
    logs = session.exec(select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.created_at.desc())).all()
    return logs[:200]
