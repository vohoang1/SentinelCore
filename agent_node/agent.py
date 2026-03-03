"""
HoangSec Agent — Main Orchestrator
Runs as systemd service: hoangsec-agent.service
"""
import logging
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from wp_engine.wp.wp_parser import parse_file
from wp_engine.wp.recon_detector import is_recon, is_malicious_ua, is_wp_login_attempt
from wp_engine.wp.xmlrpc_detector import is_xmlrpc_abuse
from wp_engine.wp import lifecycle_detector
from wp_engine.intelligence.scoring_engine import ScoringEngine
from agent_node import webshell_detector, ip_blocker, central_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("hoangsec-agent")

LOG_PATHS = [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
]
BLOCKLIST_SYNC_INTERVAL = 30   # seconds
SITE = os.getenv("HOANGSEC_SITE_ID", "unknown")

_running = True
_local_blocked: set[str] = set()
_scoring_engine = ScoringEngine()


def _handle_event(event: dict):
    ip = event["ip"]
    flags = {}

    # ── Detection layer ───────────────────────────────────────────────────────
    flags["recon"]        = is_recon(event)
    flags["xmlrpc_abuse"] = is_xmlrpc_abuse(event)
    flags["wp_login_fail"]= is_wp_login_attempt(event)
    flags["malicious_ua"] = is_malicious_ua(event)

    lifecycle_state = lifecycle_detector.track_event(event)
    if flags["recon"]:
        lifecycle_detector.mark_recon(ip)
    flags["lifecycle_hit"] = lifecycle_detector.is_full_lifecycle(ip)

    webshell_flags = webshell_detector.analyze(event)
    flags["webshell"] = webshell_flags["is_webshell"]

    score = _scoring_engine.update_score(ip, flags)
    triggered = [k for k, v in flags.items() if v]

    if not triggered:
        return

    logger.info("ALERT ip=%-18s score=%5.1f flags=%s", ip, score, triggered)

    # ── Block locally if threshold reached ───────────────────────────────────
    if _scoring_engine.should_block(ip) and ip not in _local_blocked:
        if ip_blocker.block_ip(ip):
            _local_blocked.add(ip)
            logger.warning("BLOCKED ip=%s locally", ip)

    # ── Report to Central Threat Server ──────────────────────────────────────
    central_client.submit_event(
        event_type=triggered[0] if triggered else "unknown",
        source_ip=ip,
        path=event.get("path", ""),
        score=score,
        raw_payload={"flags": triggered, "path": event.get("path")},
    )


def _sync_blocklist():
    """Pull current blocklist from central server and sync firewall rules."""
    global _local_blocked
    new_list = central_client.pull_blocklist()
    if new_list:
        added, removed = ip_blocker.sync_blocklist(_local_blocked, new_list)
        _local_blocked = set(new_list)
        if added or removed:
            logger.info("Blocklist sync: +%d -%d", added, removed)


def _watch_log(log_path: str):
    """Tail a log file at end, yielding new lines."""
    import io
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # Seek to end
        while _running:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.2)


def main():
    global _running

    def _shutdown(sig, frame):
        global _running
        logger.info("Received signal %s — shutting down", sig)
        _running = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # Find first available log
    log_path = next((p for p in LOG_PATHS if os.path.exists(p)), None)
    if not log_path:
        logger.error("No access log found at %s", LOG_PATHS)
        sys.exit(1)

    logger.info("HoangSec Agent started — watching %s", log_path)

    last_sync = 0

    for line in _watch_log(log_path):
        if not _running:
            break

        from wp_engine.wp.wp_parser import parse_line
        event = parse_line(line)
        if event:
            _handle_event(event)

        # Periodic blocklist sync
        now = time.time()
        if now - last_sync >= BLOCKLIST_SYNC_INTERVAL:
            _sync_blocklist()
            last_sync = now

    logger.info("Agent stopped cleanly.")


if __name__ == "__main__":
    main()
