import math
import re
import time
from collections import defaultdict
from typing import Optional

# ── Dangerous payload patterns (memory forensic patterns in POST body) ────────
DANGEROUS_PATTERNS = re.compile(
    r"(system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|"
    r"base64_decode\s*\(|eval\s*\(|chmod\s+777|\/bin\/sh|\/bin\/bash)",
    re.IGNORECASE,
)

# ── Webshell filename characteristics ─────────────────────────────────────────
WEBSHELL_EXTENSIONS = {".php", ".php5", ".phtml", ".shtml", ".asp", ".aspx"}
HIGH_ENTROPY_THRESHOLD = 4.5   # Shannon entropy threshold
MIN_RANDOM_FILENAME_LEN = 8    # e.g. "kdjhskdjhs.php"

# ── Rapid-access tracker: upload_path → first_seen timestamp ─────────────────
_upload_times: dict[str, float] = {}
RAPID_ACCESS_WINDOW_SECS = 30   # Flag if accessed within 30s of upload


def filename_entropy(name: str) -> float:
    """Calculate Shannon entropy of a filename. High entropy = random-looking."""
    if not name:
        return 0.0
    freq = defaultdict(int)
    for ch in name:
        freq[ch] += 1
    length = len(name)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_suspicious_filename(path: str) -> bool:
    """
    Flag filenames that look like webshells:
    - High Shannon entropy (random-looking names like 'kd7hs92j.php')
    - Executable web extension in upload directory
    """
    import os
    basename = os.path.basename(path)
    stem, ext = os.path.splitext(basename)

    if ext.lower() not in WEBSHELL_EXTENSIONS:
        return False

    if len(stem) >= MIN_RANDOM_FILENAME_LEN:
        entropy = filename_entropy(stem)
        if entropy >= HIGH_ENTROPY_THRESHOLD:
            return True

    return False


def track_upload(path: str):
    """Record when a file was uploaded (POST to upload path)."""
    _upload_times[path] = time.time()


def is_rapid_access(path: str) -> bool:
    """
    True if a file is accessed via GET shortly after a POST upload.
    Indicates attacker confirming webshell is accessible.
    """
    upload_ts = _upload_times.get(path)
    if upload_ts is None:
        return False
    elapsed = time.time() - upload_ts
    return elapsed <= RAPID_ACCESS_WINDOW_SECS


def check_post_body(body: Optional[str]) -> bool:
    """Scan POST body for dangerous PHP/shell patterns."""
    if not body:
        return False
    return bool(DANGEROUS_PATTERNS.search(body))


def analyze(event: dict, post_body: Optional[str] = None) -> dict:
    """
    Full webshell analysis for a single HTTP event.

    Returns a dict of detected flags:
      suspicious_filename, rapid_access, dangerous_payload
    and a boolean 'is_webshell' if any flag is True.
    """
    path = event.get("path", "")
    method = event.get("method", "GET")

    flags = {
        "suspicious_filename": is_suspicious_filename(path),
        "rapid_access": False,
        "dangerous_payload": False,
    }

    if method == "POST" and "/wp-content/uploads/" in path:
        track_upload(path)

    if method == "GET":
        flags["rapid_access"] = is_rapid_access(path)

    if method == "POST":
        flags["dangerous_payload"] = check_post_body(post_body)

    flags["is_webshell"] = any([
        flags["suspicious_filename"],
        flags["rapid_access"],
        flags["dangerous_payload"],
    ])

    return flags
