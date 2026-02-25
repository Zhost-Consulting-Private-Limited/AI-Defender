"""initial schema

Revision ID: 20260225_0001
Revises: 
Create Date: 2026-02-25 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260225_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "agent",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("os_type", sa.String(), nullable=False),
        sa.Column("agent_version", sa.String(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("health_score", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id"),
    )
    op.create_index(op.f("ix_agent_endpoint_id"), "agent", ["endpoint_id"], unique=True)
    op.create_index(op.f("ix_agent_tenant_id"), "agent", ["tenant_id"], unique=False)

    op.create_table(
        "event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("payload", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_event_created_at"), "event", ["created_at"], unique=False)
    op.create_index(op.f("ix_event_endpoint_id"), "event", ["endpoint_id"], unique=False)
    op.create_index(op.f("ix_event_event_type"), "event", ["event_type"], unique=False)
    op.create_index(op.f("ix_event_tenant_id"), "event", ["tenant_id"], unique=False)

    op.create_table(
        "riskscore",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("endpoint_id", sa.String(), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("insider_probability", sa.Float(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_riskscore_created_at"), "riskscore", ["created_at"], unique=False)
    op.create_index(op.f("ix_riskscore_tenant_id"), "riskscore", ["tenant_id"], unique=False)

    op.create_table(
        "incident",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("mitre_technique", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_incident_endpoint_id"), "incident", ["endpoint_id"], unique=False)
    op.create_index(op.f("ix_incident_status"), "incident", ["status"], unique=False)
    op.create_index(op.f("ix_incident_tenant_id"), "incident", ["tenant_id"], unique=False)

    op.create_table(
        "policy",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("definition", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_policy_tenant_id"), "policy", ["tenant_id"], unique=False)

    op.create_table(
        "command",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_command_endpoint_id"), "command", ["endpoint_id"], unique=False)
    op.create_index(op.f("ix_command_status"), "command", ["status"], unique=False)
    op.create_index(op.f("ix_command_tenant_id"), "command", ["tenant_id"], unique=False)

    op.create_table(
        "hourlyreport",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.Column("summary", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_hourlyreport_generated_at"), "hourlyreport", ["generated_at"], unique=False)
    op.create_index(op.f("ix_hourlyreport_tenant_id"), "hourlyreport", ["tenant_id"], unique=False)

    op.create_table(
        "auditlog",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_auditlog_created_at"), "auditlog", ["created_at"], unique=False)
    op.create_index(op.f("ix_auditlog_tenant_id"), "auditlog", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_auditlog_tenant_id"), table_name="auditlog")
    op.drop_index(op.f("ix_auditlog_created_at"), table_name="auditlog")
    op.drop_table("auditlog")
    op.drop_index(op.f("ix_hourlyreport_tenant_id"), table_name="hourlyreport")
    op.drop_index(op.f("ix_hourlyreport_generated_at"), table_name="hourlyreport")
    op.drop_table("hourlyreport")
    op.drop_index(op.f("ix_command_tenant_id"), table_name="command")
    op.drop_index(op.f("ix_command_status"), table_name="command")
    op.drop_index(op.f("ix_command_endpoint_id"), table_name="command")
    op.drop_table("command")
    op.drop_index(op.f("ix_policy_tenant_id"), table_name="policy")
    op.drop_table("policy")
    op.drop_index(op.f("ix_incident_tenant_id"), table_name="incident")
    op.drop_index(op.f("ix_incident_status"), table_name="incident")
    op.drop_index(op.f("ix_incident_endpoint_id"), table_name="incident")
    op.drop_table("incident")
    op.drop_index(op.f("ix_riskscore_tenant_id"), table_name="riskscore")
    op.drop_index(op.f("ix_riskscore_created_at"), table_name="riskscore")
    op.drop_table("riskscore")
    op.drop_index(op.f("ix_event_tenant_id"), table_name="event")
    op.drop_index(op.f("ix_event_event_type"), table_name="event")
    op.drop_index(op.f("ix_event_endpoint_id"), table_name="event")
    op.drop_index(op.f("ix_event_created_at"), table_name="event")
    op.drop_table("event")
    op.drop_index(op.f("ix_agent_tenant_id"), table_name="agent")
    op.drop_index(op.f("ix_agent_endpoint_id"), table_name="agent")
    op.drop_table("agent")
    op.drop_table("tenant")
