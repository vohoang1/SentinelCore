"""
IP Blocker — iptables (primary) + nftables (fallback)
Linux only. Must run as root or with CAP_NET_ADMIN.
"""
import subprocess
import logging

logger = logging.getLogger(__name__)


def _run(cmd: list[str]) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.error("Command failed %s: %s", cmd, e)
        return False


def _iptables_available() -> bool:
    return _run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])


def block_ip(ip: str) -> bool:
    """Block an IP via iptables (primary) or nftables (fallback)."""
    if _iptables_available():
        # Check if rule already exists to avoid duplicates
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
        if check.returncode == 0:
            return True  # Already blocked

        ok = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        if ok:
            logger.info("Blocked %s via iptables", ip)
            return True

    # Fallback: nftables
    ok = _run([
        "nft", "add", "rule", "inet", "filter", "input",
        "ip", "saddr", ip, "drop",
    ])
    if ok:
        logger.info("Blocked %s via nftables", ip)
        return True

    logger.error("Failed to block %s — no firewall available", ip)
    return False


def unblock_ip(ip: str) -> bool:
    """Remove an IP block (iptables only; nftables requires handle lookup)."""
    ok = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if ok:
        logger.info("Unblocked %s", ip)
    return ok


def sync_blocklist(current_blocked: set[str], new_blocklist: list[str]) -> tuple[int, int]:
    """
    Sync local firewall rules with the central server blocklist.
    Returns (added, removed) counts.
    """
    new_set = set(new_blocklist)
    to_add = new_set - current_blocked
    to_remove = current_blocked - new_set

    added = sum(1 for ip in to_add if block_ip(ip))
    removed = sum(1 for ip in to_remove if unblock_ip(ip))

    return added, removed
