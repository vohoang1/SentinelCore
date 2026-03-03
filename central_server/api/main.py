"""
HoangSec Central Threat Server — FastAPI Application
"""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, func
from sqlalchemy.orm import Session, sessionmaker

from ..db.models import Agent, Base, BlockedIP, Event, Report, Server, Tenant
from .auth import verify_agent, verify_api_key
from .threat_intel import get_blocklist_for_tenant, get_ip_risk_score, propagate_block_if_needed

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hoangsec:hoangsec@localhost/hoangsec")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

templates = Jinja2Templates(directory="central_server/templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="HoangSec Central Threat Server", version="1.0.0", lifespan=lifespan)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class EventPayload(BaseModel):
    event_type: str
    source_ip: str
    path: str | None = None
    score: float = 0
    raw_payload: dict | None = None
    occurred_at: datetime | None = None


class AgentRegisterPayload(BaseModel):
    hostname: str
    ip_address: str
    cert_fingerprint: str
    version: str = "1.0.0"


# ── Agent API Routes ──────────────────────────────────────────────────────────

@app.post("/api/v1/agents/register")
async def register_agent(
    payload: AgentRegisterPayload,
    tenant: Tenant = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Register a new agent. Returns its DB ID for future event submission."""
    server = Server(
        tenant_id=tenant.id,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        last_seen=datetime.now(timezone.utc),
    )
    db.add(server)
    db.flush()

    agent = Agent(
        server_id=server.id,
        cert_fingerprint=payload.cert_fingerprint,
        version=payload.version,
    )
    db.add(agent)
    db.commit()
    return {"status": "registered", "agent_id": agent.id}


@app.post("/api/v1/events")
async def ingest_event(
    payload: EventPayload,
    agent: Agent = Depends(verify_agent),
    tenant: Tenant = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Receive a security event from an agent."""
    event = Event(
        agent_id=agent.id,
        tenant_id=tenant.id,
        event_type=payload.event_type,
        source_ip=payload.source_ip,
        path=payload.path,
        score=payload.score,
        raw_payload=payload.raw_payload,
        occurred_at=payload.occurred_at or datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()

    # Evaluate and propagate block if risk score crosses threshold
    total_score = get_ip_risk_score(payload.source_ip, db)
    propagate_block_if_needed(payload.source_ip, tenant.id, total_score, db)

    return {"status": "accepted", "total_score": total_score}


@app.get("/api/v1/blocklist")
async def pull_blocklist(
    tenant: Tenant = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Agent pulls this every 30s to sync its local iptables/nftables rules."""
    ips = get_blocklist_for_tenant(tenant.id, db)
    return {"count": len(ips), "blocked_ips": ips}


# ── Admin Dashboard Routes ────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    stats = {
        "total_blocked_ips": db.query(func.count(BlockedIP.id)).scalar(),
        "total_events_today": db.query(func.count(Event.id)).filter(
            func.date(Event.occurred_at) == func.current_date()
        ).scalar(),
        "total_servers": db.query(func.count(Server.id)).scalar(),
        "total_tenants": db.query(func.count(Tenant.id)).scalar(),
    }

    top_attackers = db.query(
        Event.source_ip,
        func.sum(Event.score).label("total_score"),
        func.count(Event.id).label("event_count"),
    ).group_by(Event.source_ip).order_by(func.sum(Event.score).desc()).limit(10).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "top_attackers": top_attackers,
    })


@app.get("/reports/{tenant_id}", response_class=HTMLResponse)
async def report_view(request: Request, tenant_id: int, db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    report = db.query(Report).filter(
        Report.tenant_id == tenant_id
    ).order_by(Report.month.desc()).first()

    return templates.TemplateResponse("report.html", {
        "request": request,
        "tenant": tenant,
        "report": report,
    })
