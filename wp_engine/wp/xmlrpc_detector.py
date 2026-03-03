def is_xmlrpc_abuse(event: dict) -> bool:
    """
    Detect XML-RPC abuse (common vector for brute force and DDoS amplification).
    Any POST to /xmlrpc.php is flagged — legitimate usage is rare and
    should be disabled on hardened WordPress installs.
    """
    return (
        event.get("path", "").rstrip("?").rstrip("/") == "/xmlrpc.php"
        and event.get("method") == "POST"
    )
