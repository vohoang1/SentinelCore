from sqlalchemy import func
from sqlalchemy.orm import Session
from ..db.models import BlockedIP, Event, Tenant

GLOBAL_BLOCK_THRESHOLD = 80.0    # Score to trigger global block (cross-tenant)
TENANT_BLOCK_THRESHOLD = 50.0    # Score to block within a tenant
PROPAGATION_SCORE_BOOST = 30.0   # Extra score added when confirmed by multiple tenants


def get_ip_risk_score(ip: str, db: Session) -> float:
    """Aggregate total risk score for an IP across all recent events (last 24h)."""
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    result = db.query(func.sum(Event.score)).filter(
        Event.source_ip == ip,
        Event.occurred_at >= cutoff,
    ).scalar()

    return float(result or 0)


def propagate_block_if_needed(ip: str, tenant_id: int, score: float, db: Session):
    """
    Evaluate risk score and propagate block:
    - score >= GLOBAL_BLOCK_THRESHOLD → global block (all tenants)
    - score >= TENANT_BLOCK_THRESHOLD → block within this tenant only
    """
    if score >= GLOBAL_BLOCK_THRESHOLD:
        _upsert_block(ip=ip, tenant_id=None, reason="global_threshold_exceeded", score=score, db=db)
    elif score >= TENANT_BLOCK_THRESHOLD:
        _upsert_block(ip=ip, tenant_id=tenant_id, reason="tenant_threshold_exceeded", score=score, db=db)


def _upsert_block(ip: str, tenant_id, reason: str, score: float, db: Session):
    """Insert or update a block entry, keeping the highest score."""
    existing = db.query(BlockedIP).filter(
        BlockedIP.ip_address == ip,
        BlockedIP.tenant_id == tenant_id,
    ).first()

    if existing:
        if score > existing.risk_score:
            existing.risk_score = score
            existing.reason = reason
            db.commit()
    else:
        entry = BlockedIP(
            ip_address=ip,
            tenant_id=tenant_id,
            reason=reason,
            risk_score=score,
        )
        db.add(entry)
        db.commit()


def get_blocklist_for_tenant(tenant_id: int, db: Session) -> list[str]:
    """
    Return all IPs an agent should block:
    - Global blocks (tenant_id IS NULL)
    - Tenant-specific blocks for this tenant
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    blocks = db.query(BlockedIP.ip_address).filter(
        (BlockedIP.tenant_id == tenant_id) | (BlockedIP.tenant_id == None),
        (BlockedIP.expires_at == None) | (BlockedIP.expires_at > now),
    ).all()

    return [str(row.ip_address) for row in blocks]
