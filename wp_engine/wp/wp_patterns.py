# WordPress-specific suspicious paths and patterns
# Used by recon_detector and lifecycle_detector

SUSPICIOUS_PATHS = [
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/install.php",
    "/wp-includes/",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.env",
    "/readme.html",
    "/license.txt",
]

SUSPICIOUS_EXTENSIONS = [
    ".bak", ".zip", ".old", ".sql", ".tar",
    ".gz", ".7z", ".rar", ".log", ".swp",
]

BRUTEFORCE_PATHS = [
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-admin/",
]

UPLOAD_PATHS = [
    "/wp-content/uploads/",
]

# Known malicious user-agent fragments (lightweight blocklist)
MALICIOUS_UA_FRAGMENTS = [
    "sqlmap", "nikto", "nmap", "masscan",
    "zgrab", "wfuzz", "dirbuster", "gobuster",
    "burpsuite", "hydra", "curl/7",
]

# Scoring weights used by the scoring engine
SCORE_WEIGHTS = {
    "recon":           10,
    "xmlrpc_abuse":    15,
    "wp_login_fail":   5,
    "brute_force":     20,
    "upload_attempt":  25,
    "lifecycle_hit":   50,
    "malicious_ua":    15,
    "backup_file":     10,
}

BLOCK_THRESHOLD = 50
