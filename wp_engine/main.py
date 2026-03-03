"""
WP Engine — Main Orchestrator
Phase 5: WordPress Behavior-Aware Detection Engine

Wires together:
  WP Parser → Recon/XMLRPC/Lifecycle Detectors → Scoring Engine → Event Emitter
"""

import argparse
import sys

from wp_engine.wp.wp_parser import parse_file
from wp_engine.wp.recon_detector import is_recon, is_malicious_ua, is_wp_login_attempt
from wp_engine.wp.xmlrpc_detector import is_xmlrpc_abuse
from wp_engine.wp import lifecycle_detector
from wp_engine.intelligence.scoring_engine import ScoringEngine
from wp_engine.core.event_stream import emit_event
from wp_engine.core.log_watcher import watch_log, replay_log


def process_event(event: dict, engine: ScoringEngine, site: str):
    ip = event["ip"]
    path = event.get("path", "")
    flags = {}

    # ── Detection Layer ───────────────────────────────────────────────────────
    flags["recon"] = is_recon(event)
    flags["xmlrpc_abuse"] = is_xmlrpc_abuse(event)
    flags["wp_login_fail"] = is_wp_login_attempt(event) and event.get("status") in ("200", "302", "403")
    flags["malicious_ua"] = is_malicious_ua(event)

    # Track exploit lifecycle state machine
    lifecycle_state = lifecycle_detector.track_event(event)
    if flags["recon"]:
        lifecycle_detector.mark_recon(ip)

    flags["upload_attempt"] = lifecycle_state.get("upload", False)
    flags["lifecycle_hit"] = lifecycle_detector.is_full_lifecycle(ip)

    # ── Scoring Layer ─────────────────────────────────────────────────────────
    score = engine.update_score(ip, flags)

    # ── Emit Event (only when something was flagged) ──────────────────────────
    triggered = [k for k, v in flags.items() if v]
    if triggered:
        event_type = triggered[0]  # Primary classification = highest priority flag
        emit_event(ip=ip, event_type=f"wp_{event_type}", score=score, site=site,
                   extra={"path": path, "flags": triggered})

    # ── Block Decision ────────────────────────────────────────────────────────
    if engine.should_block(ip):
        emit_event(ip=ip, event_type="BLOCK_DECISION", score=score, site=site,
                   extra={"reason": "score_threshold_exceeded"})


def main():
    parser = argparse.ArgumentParser(
        description="WP Engine — WordPress Behavior-Aware Detection Engine"
    )
    parser.add_argument("log", help="Path to Nginx/Apache access log")
    parser.add_argument("--site", default="unknown", help="Site identifier for events")
    parser.add_argument("--watch", action="store_true",
                        help="Tail log in real-time instead of full replay")
    args = parser.parse_args()

    engine = ScoringEngine()

    if args.watch:
        print(f"[WP Engine] Watching: {args.log}", file=sys.stderr)
        watch_log(args.log, lambda evt: process_event(evt, engine, args.site))
    else:
        print(f"[WP Engine] Replaying: {args.log}", file=sys.stderr)
        replay_log(args.log, lambda evt: process_event(evt, engine, args.site))

        # Print threat summary after replay
        print("\n[WP Engine] Top Threats:", file=sys.stderr)
        for ip, score in engine.top_threats(10):
            status = "BLOCKED" if engine.should_block(ip) else "MONITORING"
            print(f"  {ip:20s}  score={score:6.1f}  [{status}]", file=sys.stderr)


if __name__ == "__main__":
    main()
