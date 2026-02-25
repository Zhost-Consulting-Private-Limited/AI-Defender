from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from .auth import require_role
from .db import get_session, init_db
from .models import Agent, Command, HourlyReport, Incident, Policy, RiskScore, Tenant
from .schemas import (
    AgentEnrollRequest,
    CommandInput,
    EventBatch,
    IncidentBulkStatusUpdate,
    IncidentStatusUpdate,
    PolicyInput,
    SIEMForwardRequest,
)
from .services import add_audit, create_hourly_report, dequeue_commands, forward_incidents_to_siem, process_events

app = FastAPI(title="Behavioral Security Platform API", version="2.3.0")
templates = Jinja2Templates(directory="backend/app/templates")
app.mount("/static", StaticFiles(directory="backend/app/static"), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/v1/tenants", dependencies=[Depends(require_role("admin"))])
def create_tenant(name: str, session: Session = Depends(get_session)):
    tenant = Tenant(name=name)
    session.add(tenant)
    session.commit()
    session.refresh(tenant)
    add_audit(session, tenant.id or 0, "admin", "create_tenant", "tenant", str(tenant.id))
    session.commit()
    return {"id": tenant.id, "name": tenant.name, "created_at": tenant.created_at}


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


@app.get("/api/v1/incidents", dependencies=[Depends(require_role("analyst", "admin"))])
def list_incidents(
    tenant_id: int,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    endpoint_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    session: Session = Depends(get_session),
):
    query = select(Incident).where(Incident.tenant_id == tenant_id)

    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if endpoint_id:
        query = query.where(Incident.endpoint_id == endpoint_id)

    incidents = session.exec(query.order_by(Incident.created_at.desc())).all()[:limit]
    return incidents


@app.patch("/api/v1/incidents/{incident_id}/status", dependencies=[Depends(require_role("analyst", "admin"))])
def update_incident_status(incident_id: int, payload: IncidentStatusUpdate, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="incident not found")

    incident.status = payload.status
    session.add(incident)
    add_audit(session, incident.tenant_id, "analyst", "update_incident_status", "incident", str(incident_id))
    session.commit()
    session.refresh(incident)

    return {
        "status": "updated",
        "incident": incident,
    }


@app.post("/api/v1/incidents/bulk-status", dependencies=[Depends(require_role("analyst", "admin"))])
def bulk_update_incident_status(payload: IncidentBulkStatusUpdate, session: Session = Depends(get_session)):
    incident_id_set = set(payload.incident_ids)
    if not incident_id_set:
        raise HTTPException(status_code=400, detail="incident_ids must not be empty")

    incidents = session.exec(
        select(Incident).where(Incident.tenant_id == payload.tenant_id, Incident.id.in_(incident_id_set))
    ).all()

    for incident in incidents:
        incident.status = payload.status
        session.add(incident)

    add_audit(session, payload.tenant_id, "analyst", "bulk_update_incident_status", "tenant", str(payload.tenant_id))
    session.commit()

    return {
        "status": "updated",
        "requested": len(incident_id_set),
        "updated": len(incidents),
        "target_status": payload.status,
    }


@app.post("/api/v1/integrations/siem/forward", dependencies=[Depends(require_role("analyst", "admin"))])
def forward_siem(payload: SIEMForwardRequest, session: Session = Depends(get_session)):
    try:
        return forward_incidents_to_siem(
            session,
            payload.tenant_id,
            payload.provider,
            payload.webhook_url,
            payload.max_incidents,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"SIEM forward failed: {exc}") from exc


@app.post("/api/v1/reports/hourly", dependencies=[Depends(require_role("analyst", "admin"))])
def hourly_report(tenant_id: int, session: Session = Depends(get_session)):
    return create_hourly_report(session, tenant_id)


@app.get("/api/v1/reports", dependencies=[Depends(require_role("analyst", "admin"))])
def list_reports(tenant_id: int, session: Session = Depends(get_session)):
    reports = session.exec(
        select(HourlyReport).where(HourlyReport.tenant_id == tenant_id).order_by(HourlyReport.generated_at.desc())
    ).all()
    return reports[:50]
