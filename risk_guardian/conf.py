from django.conf import settings

DEFAULTS = {
    "ENABLED": True,
    "CACHE_BACKEND": "default",
    "CACHE_PREFIX": "rg",
    "LOG_ALL_SCORES": False,
    "SCORE_THRESHOLD_BLOCK": 80,
    "SCORE_THRESHOLD_CHALLENGE": 50,
    "BLOCK_RESPONSE_CODE": 429,
    "BLOCK_TTL_SECONDS": 3600,
    "HISTORY_WINDOW_SECONDS": 300,
    "HISTORY_MAX_REQUESTS": 100,
    "IGNORE_PATHS": [
        "/health/",
        "/metrics/",
        "/__debug__/",
        "/favicon.ico",
    ],
    # Client IP resolution. By default only REMOTE_ADDR is used: a header set
    # by the client can be forged. Set CLIENT_IP_HEADER (a META key, e.g.
    # "HTTP_X_FORWARDED_FOR") and list the proxies that set it in
    # TRUSTED_PROXIES; the header is read only when the request comes from one.
    "CLIENT_IP_HEADER": None,
    "TRUSTED_PROXIES": [],
    # IPs and networks (CIDR) that are never scored nor blocked.
    "ALLOWLIST_IPS": [],
    # Scan paths added to the built-in list of PatternAnalyzer.
    "EXTRA_SCAN_PATHS": [],
    # Authentication tracking (logins and signups per IP), read by AuthAnalyzer.
    "AUTH_WINDOW_SECONDS": 3600,
    "AUTH_ACCOUNTS_MONITOR": 3,
    "AUTH_ACCOUNTS_CHALLENGE": 5,
    "AUTH_FAILED_ACCOUNTS_CHALLENGE": 3,
    "AUTH_FAILED_ACCOUNTS_BLOCK": 5,
    "AUTH_SIGNUPS_CHALLENGE": 3,
    "ANALYZERS": [
        "risk_guardian.analyzers.RateAnalyzer",
        "risk_guardian.analyzers.UserAgentAnalyzer",
        "risk_guardian.analyzers.SessionAnalyzer",
        "risk_guardian.analyzers.PatternAnalyzer",
        "risk_guardian.analyzers.TimingAnalyzer",
        "risk_guardian.analyzers.AuthAnalyzer",
    ],
}


def get_config():
    user_config = getattr(settings, "RISK_GUARDIAN", {})
    merged = {**DEFAULTS, **user_config}
    return merged
