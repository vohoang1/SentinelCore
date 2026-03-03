from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, ForeignKey,
    Integer, Numeric, String, Text, func
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id         = Column(Integer, primary_key=True)
    name       = Column(String(255), nullable=False)
    api_key    = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active  = Column(Boolean, default=True)

    servers    = relationship("Server", back_populates="tenant", cascade="all, delete")
    events     = relationship("Event", back_populates="tenant")


class Server(Base):
    __tablename__ = "servers"

    id         = Column(Integer, primary_key=True)
    tenant_id  = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    hostname   = Column(String(255), nullable=False)
    ip_address = Column(INET, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    last_seen  = Column(DateTime)

    tenant     = relationship("Tenant", back_populates="servers")
    agents     = relationship("Agent", back_populates="server", cascade="all, delete")


class Agent(Base):
    __tablename__ = "agents"

    id               = Column(Integer, primary_key=True)
    server_id        = Column(Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    cert_fingerprint = Column(String(128), unique=True, nullable=False)
    version          = Column(String(32))
    registered_at    = Column(DateTime, server_default=func.now())
    is_active        = Column(Boolean, default=True)

    server = relationship("Server", back_populates="agents")


class Event(Base):
    __tablename__ = "events"

    id          = Column(BigInteger, primary_key=True)
    agent_id    = Column(Integer, ForeignKey("agents.id"), nullable=False)
    tenant_id   = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    event_type  = Column(String(64), nullable=False)
    source_ip   = Column(INET, nullable=False)
    path        = Column(Text)
    score       = Column(Numeric(6, 2), default=0)
    raw_payload = Column(JSONB)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("Tenant", back_populates="events")


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id         = Column(Integer, primary_key=True)
    ip_address = Column(INET, nullable=False)
    tenant_id  = Column(Integer, ForeignKey("tenants.id"), nullable=True)  # None = global
    reason     = Column(String(255))
    risk_score = Column(Numeric(6, 2), default=0)
    blocked_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    blocked_by = Column(Integer, ForeignKey("agents.id"), nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id                    = Column(Integer, primary_key=True)
    tenant_id             = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    month                 = Column(DateTime, nullable=False)
    protected_sites       = Column(Integer, default=0)
    total_attacks_blocked = Column(Integer, default=0)
    webshell_attempts     = Column(Integer, default=0)
    brute_force_attempts  = Column(Integer, default=0)
    unique_malicious_ips  = Column(Integer, default=0)
    effectiveness_pct     = Column(Numeric(5, 2))
    generated_at          = Column(DateTime, server_default=func.now())
    pdf_path              = Column(Text)
