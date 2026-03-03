import re
from typing import Optional

# Nginx/Apache combined log format pattern
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]*)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_line(line: str) -> Optional[dict]:
    """
    Parse a single Nginx/Apache combined log line.

    Returns a structured event dict or None if the line doesn't match.
    """
    line = line.strip()
    if not line:
        return None

    match = LOG_PATTERN.match(line)
    if not match:
        return None

    return match.groupdict()


def parse_file(path: str):
    """
    Generator: yields parsed events from a log file, skipping malformed lines.
    Memory-efficient — never loads the full file into RAM.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line)
            if event:
                yield event
