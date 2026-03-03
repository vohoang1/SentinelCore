from ..wp.wp_patterns import SCORE_WEIGHTS, BLOCK_THRESHOLD
from ..wp.lifecycle_detector import is_full_lifecycle


class ScoringEngine:
    """
    Behavioral scoring engine — maintains per-IP cumulative risk scores.

    Scores accumulate across all events for an IP within a session.
    When score >= BLOCK_THRESHOLD, the IP should be blocked.
    Designed to be stateless between restarts (no persistence layer yet).
    """

    def __init__(self):
        self._ip_scores: dict[str, float] = {}

    def update_score(self, ip: str, event_flags: dict) -> float:
        """
        Apply score deltas based on detected event flags.

        event_flags keys (all bool):
          recon, xmlrpc_abuse, wp_login_fail, brute_force,
          upload_attempt, malicious_ua, lifecycle_hit
        """
        score = self._ip_scores.get(ip, 0.0)

        for flag, weight in SCORE_WEIGHTS.items():
            if event_flags.get(flag):
                score += weight

        # Full lifecycle escalation: overrides all other scoring
        if is_full_lifecycle(ip):
            score += SCORE_WEIGHTS["lifecycle_hit"]

        self._ip_scores[ip] = round(score, 2)
        return self._ip_scores[ip]

    def get_score(self, ip: str) -> float:
        return self._ip_scores.get(ip, 0.0)

    def should_block(self, ip: str) -> bool:
        return self.get_score(ip) >= BLOCK_THRESHOLD

    def top_threats(self, n: int = 10) -> list[tuple[str, float]]:
        """Return top N IPs by score, descending."""
        return sorted(self._ip_scores.items(), key=lambda x: x[1], reverse=True)[:n]

    def reset(self, ip: str):
        """Clear score for an IP (e.g., after successful block)."""
        self._ip_scores.pop(ip, None)
