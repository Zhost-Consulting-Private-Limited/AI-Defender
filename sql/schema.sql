-- Multi-tenant schema for behavioral intelligence platform

CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    external_identity TEXT NOT NULL,
    role TEXT NOT NULL,
    department TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE endpoints (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    hostname TEXT NOT NULL,
    os_type TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    health_score INT NOT NULL DEFAULT 100,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE behavioral_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    endpoint_id UUID REFERENCES endpoints(id),
    event_type TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    integrity_hash TEXT NOT NULL
);

CREATE TABLE file_integrity_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id),
    path TEXT NOT NULL,
    event_action TEXT NOT NULL,
    sha256_before TEXT,
    sha256_after TEXT,
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    event_time TIMESTAMPTZ NOT NULL
);

CREATE TABLE risk_scores (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    endpoint_id UUID REFERENCES endpoints(id),
    risk_score NUMERIC(5,2) NOT NULL,
    insider_threat_probability NUMERIC(5,2) NOT NULL,
    deviation_score NUMERIC(5,2) NOT NULL,
    explanation JSONB,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE incidents (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    mitre_techniques TEXT[] NOT NULL,
    status TEXT NOT NULL,
    assigned_to TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE hourly_reports (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    report_hour TIMESTAMPTZ NOT NULL,
    summary JSONB NOT NULL,
    delivered_channels TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_behavioral_events_tenant_time ON behavioral_events(tenant_id, event_time DESC);
CREATE INDEX idx_risk_scores_tenant_time ON risk_scores(tenant_id, calculated_at DESC);
CREATE INDEX idx_incidents_tenant_status ON incidents(tenant_id, status);
