-- ─────────────────────────────────────────────────────────────────────────────
-- HoangSec Multi-Tenant Security Platform — PostgreSQL Schema
-- ─────────────────────────────────────────────────────────────────────────────

-- One Hosting Provider = one Tenant
CREATE TABLE tenants (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    api_key     VARCHAR(64)  NOT NULL UNIQUE,  -- SHA256 of issued key
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active   BOOLEAN DEFAULT TRUE
);

-- Customer servers belonging to a tenant
CREATE TABLE servers (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname    VARCHAR(255) NOT NULL,
    ip_address  INET NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMP
);

-- Agent instances (one per server, unique cert fingerprint)
CREATE TABLE agents (
    id              SERIAL PRIMARY KEY,
    server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    cert_fingerprint VARCHAR(128) UNIQUE NOT NULL,
    version         VARCHAR(32),
    registered_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    is_active       BOOLEAN DEFAULT TRUE
);

-- Raw security events from agents
CREATE TABLE events (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        INTEGER NOT NULL REFERENCES agents(id),
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    event_type      VARCHAR(64) NOT NULL,   -- wp_recon, xmlrpc_abuse, webshell, brute_force
    source_ip       INET NOT NULL,
    path            TEXT,
    score           NUMERIC(6,2) DEFAULT 0,
    raw_payload     JSONB,
    occurred_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_events_source_ip    ON events (source_ip);
CREATE INDEX idx_events_tenant_id    ON events (tenant_id);
CREATE INDEX idx_events_occurred_at  ON events (occurred_at);

-- Global + per-tenant IP blocklist
CREATE TABLE blocked_ips (
    id              SERIAL PRIMARY KEY,
    ip_address      INET NOT NULL,
    tenant_id       INTEGER REFERENCES tenants(id),  -- NULL = global block
    reason          VARCHAR(255),
    risk_score      NUMERIC(6,2) DEFAULT 0,
    blocked_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE,        -- NULL = permanent
    blocked_by      INTEGER REFERENCES agents(id),
    UNIQUE (ip_address, tenant_id)
);
CREATE INDEX idx_blocked_ips_ip        ON blocked_ips (ip_address);
CREATE INDEX idx_blocked_ips_tenant    ON blocked_ips (tenant_id);

-- Aggregated monthly reports per tenant
CREATE TABLE reports (
    id                      SERIAL PRIMARY KEY,
    tenant_id               INTEGER NOT NULL REFERENCES tenants(id),
    month                   DATE NOT NULL,              -- First day of month
    protected_sites         INTEGER DEFAULT 0,
    total_attacks_blocked   INTEGER DEFAULT 0,
    webshell_attempts       INTEGER DEFAULT 0,
    brute_force_attempts    INTEGER DEFAULT 0,
    unique_malicious_ips    INTEGER DEFAULT 0,
    effectiveness_pct       NUMERIC(5,2),
    generated_at            TIMESTAMP DEFAULT NOW(),
    pdf_path                TEXT,
    UNIQUE (tenant_id, month)
);
