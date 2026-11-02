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
    "ANALYZERS": [
        "risk_guardian.analyzers.RateAnalyzer",
        "risk_guardian.analyzers.UserAgentAnalyzer",
        "risk_guardian.analyzers.SessionAnalyzer",
        "risk_guardian.analyzers.PatternAnalyzer",
        "risk_guardian.analyzers.TimingAnalyzer",
    ],
}


def get_config():
    user_config = getattr(settings, "RISK_GUARDIAN", {})
    merged = {**DEFAULTS, **user_config}
    return merged
