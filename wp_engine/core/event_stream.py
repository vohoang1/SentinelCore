import json
import sys
from datetime import datetime, timezone
from typing import Optional


def emit_event(
    ip: str,
    event_type: str,
    score: float,
    site: str = "unknown",
    extra: Optional[dict] = None,
) -> dict:
    """
    Emit a normalized security event to stdout (NDJSON format).

    The intelligence hub downstream consumes this stream.
    Output format matches the Phase 5 spec:
    {
      "ip": "1.2.3.4",
      "type": "wp_recon",
      "site": "example.com",
      "score": 45,
      "timestamp": "2026-03-03T21:00:00Z"
    }
    """
    record = {
        "ip": ip,
        "type": event_type,
        "site": site,
        "score": round(score, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    if extra:
        record.update(extra)

    print(json.dumps(record), flush=True)
    return record
