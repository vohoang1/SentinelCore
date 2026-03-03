from .wp_patterns import SUSPICIOUS_PATHS, SUSPICIOUS_EXTENSIONS, MALICIOUS_UA_FRAGMENTS


def is_recon(event: dict) -> bool:
    """
    Detect WordPress reconnaissance activity:
    - Probing known sensitive paths (plugins, admin-ajax, wp-config)
    - Requesting backup/archive file extensions
    """
    path = event.get("path", "").lower()

    if any(p in path for p in SUSPICIOUS_PATHS):
        return True

    if any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        return True

    return False


def is_malicious_ua(event: dict) -> bool:
    """
    Detect known scanner/attack tool user-agents.
    """
    ua = event.get("ua", "").lower()
    return any(fragment in ua for fragment in MALICIOUS_UA_FRAGMENTS)


def is_wp_login_attempt(event: dict) -> bool:
    """Detect authentication attempts against wp-login."""
    return (
        event.get("path", "").startswith("/wp-login.php")
        and event.get("method") == "POST"
    )


def is_admin_access(event: dict) -> bool:
    """Detect any access to wp-admin area."""
    return "/wp-admin/" in event.get("path", "")
