import time
import os
from ..wp.wp_parser import parse_file


def watch_log(log_path: str, callback, poll_interval: float = 0.5):
    """
    Tail a log file in real-time, yielding new lines as they arrive.
    Uses seek-based polling — no inotify dependency, works on Windows and Linux.

    callback: called with each parsed event dict
    """
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        # Start at end of file — only process new events
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                from ..wp.wp_parser import parse_line
                event = parse_line(line)
                if event:
                    callback(event)
            else:
                time.sleep(poll_interval)


def replay_log(log_path: str, callback):
    """
    Process an entire existing log file top-to-bottom.
    Used for: initial load, forensic replay, benchmark testing.
    """
    for event in parse_file(log_path):
        callback(event)
