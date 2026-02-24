from typing import Any, Optional
from pydantic import BaseModel


class AgentEnrollRequest(BaseModel):
    tenant_id: int
    endpoint_id: str
    hostname: str
    os_type: str
    agent_version: str


class EventInput(BaseModel):
    user_id: Optional[str] = None
    event_type: str
    severity: str
    payload: dict[str, Any]


class EventBatch(BaseModel):
    tenant_id: int
    endpoint_id: str
    events: list[EventInput]


class PolicyInput(BaseModel):
    tenant_id: int
    name: str
    enabled: bool = True
    definition: dict[str, Any]


class CommandInput(BaseModel):
    tenant_id: int
    endpoint_id: str
    action: str
