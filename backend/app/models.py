from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field


class Tenant(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Agent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    endpoint_id: str = Field(index=True, unique=True)
    hostname: str
    os_type: str
    agent_version: str
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    health_score: int = 100


class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    endpoint_id: str = Field(index=True)
    user_id: Optional[str] = None
    event_type: str = Field(index=True)
    severity: str
    payload: str
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class RiskScore(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    user_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    score: float
    insider_probability: float
    reason: str
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class Incident(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    endpoint_id: str = Field(index=True)
    title: str
    mitre_technique: str
    severity: str
    status: str = Field(default="open", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Policy(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    name: str
    enabled: bool = True
    definition: str


class Command(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    endpoint_id: str = Field(index=True)
    action: str
    status: str = Field(default="pending", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class HourlyReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    generated_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    summary: str


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: int = Field(index=True)
    actor: str
    action: str
    resource_type: str
    resource_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
