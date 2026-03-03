from .wp_patterns import UPLOAD_PATHS


# In-memory state tracker per IP: tracks exploit kill-chain progression.
# Structure: { ip: { "recon": bool, "upload": bool, "verify": bool } }
_ip_state: dict = {}


def track_event(event: dict) -> dict:
    """
    Track exploit lifecycle stages per IP.

    Kill-chain stages:
      1. Recon   — probing WP structure
      2. Upload  — POST to wp-content/uploads (file upload attempt)
      3. Verify  — GET to the same upload path (confirming shell exists)

    Returns the current lifecycle state for the IP.
    """
    ip = event.get("ip", "unknown")
    path = event.get("path", "")
    method = event.get("method", "GET")

    if ip not in _ip_state:
        _ip_state[ip] = {"recon": False, "upload": False, "verify": False}

    state = _ip_state[ip]

    is_upload_path = any(p in path for p in UPLOAD_PATHS)

    if is_upload_path and method == "POST":
        state["upload"] = True

    if is_upload_path and method == "GET" and state["upload"]:
        state["verify"] = True

    return state


def mark_recon(ip: str):
    """Called by scoring engine when recon is detected — marks lifecycle stage."""
    if ip not in _ip_state:
        _ip_state[ip] = {"recon": False, "upload": False, "verify": False}
    _ip_state[ip]["recon"] = True


def is_full_lifecycle(ip: str) -> bool:
    """
    Returns True if an IP has completed the full exploit kill-chain:
    Recon → Upload → Verify.
    This should trigger maximum score escalation (+50).
    """
    state = _ip_state.get(ip, {})
    return state.get("recon") and state.get("upload") and state.get("verify")


def get_state(ip: str) -> dict:
    return _ip_state.get(ip, {})
