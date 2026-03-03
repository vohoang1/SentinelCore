import hashlib
import hmac
from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from .database import get_db
from ..db.models import Tenant, Agent

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=True)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def verify_api_key(
    api_key: str = Depends(API_KEY_HEADER),
    db: Session = Depends(get_db),
) -> Tenant:
    """Verify API key and return the authenticated tenant."""
    hashed = hash_api_key(api_key)
    tenant = db.query(Tenant).filter(
        Tenant.api_key == hashed,
        Tenant.is_active == True,
    ).first()

    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    return tenant


async def verify_mtls_cert(request: Request) -> str:
    """
    Verify mTLS client certificate fingerprint.
    In production: nginx/caddy terminates TLS and forwards
    the verified cert fingerprint via X-Client-Cert-Fingerprint header.
    """
    fingerprint = request.headers.get("X-Client-Cert-Fingerprint")
    if not fingerprint:
        raise HTTPException(status_code=403, detail="mTLS certificate required")
    return fingerprint


async def verify_agent(
    fingerprint: str = Depends(verify_mtls_cert),
    tenant: Tenant = Depends(verify_api_key),
    db: Session = Depends(get_db),
) -> Agent:
    """Verify that the agent cert belongs to the authenticated tenant's server."""
    agent = db.query(Agent).filter(
        Agent.cert_fingerprint == fingerprint,
        Agent.is_active == True,
    ).first()

    if not agent:
        raise HTTPException(status_code=403, detail="Unknown or inactive agent")

    return agent
