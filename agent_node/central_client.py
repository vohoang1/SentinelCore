"""
Central Server mTLS Client
Handles event submission and blocklist pull over HTTPS with mutual TLS.
"""
import logging
import os
import ssl
from typing import Optional

import urllib.request
import json

logger = logging.getLogger(__name__)

CENTRAL_URL   = os.getenv("HOANGSEC_CENTRAL_URL", "https://central.hoangsec.internal")
API_KEY       = os.getenv("HOANGSEC_API_KEY", "")
CERT_FILE     = os.getenv("HOANGSEC_CERT_FILE", "/etc/hoangsec/agent.crt")
KEY_FILE      = os.getenv("HOANGSEC_KEY_FILE", "/etc/hoangsec/agent.key")
CA_FILE       = os.getenv("HOANGSEC_CA_FILE", "/etc/hoangsec/ca.crt")


def _make_ssl_context() -> ssl.SSLContext:
    """Build mTLS SSL context: present agent cert, verify server via CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CA_FILE)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _post(path: str, payload: dict) -> Optional[dict]:
    ctx = _make_ssl_context()
    url = f"{CENTRAL_URL}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.error("POST %s failed: %s", path, e)
        return None


def _get(path: str) -> Optional[dict]:
    ctx = _make_ssl_context()
    url = f"{CENTRAL_URL}{path}"
    req = urllib.request.Request(url, headers={"X-API-Key": API_KEY})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.error("GET %s failed: %s", path, e)
        return None


def submit_event(event_type: str, source_ip: str, path: str,
                 score: float, raw_payload: Optional[dict] = None):
    """Send a security event to the central threat server."""
    from datetime import datetime, timezone
    payload = {
        "event_type": event_type,
        "source_ip": source_ip,
        "path": path,
        "score": score,
        "raw_payload": raw_payload,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }
    return _post("/api/v1/events", payload)


def pull_blocklist() -> list[str]:
    """Fetch the latest blocklist from the central server."""
    resp = _get("/api/v1/blocklist")
    if resp:
        return resp.get("blocked_ips", [])
    return []
