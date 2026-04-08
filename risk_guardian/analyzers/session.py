from __future__ import annotations

from django.core.cache import caches

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.conf import get_config
from risk_guardian.history import AccessHistory


class SessionAnalyzer(BaseAnalyzer):
    def __init__(self, auth_prefixes=None):
        self.auth_prefixes = auth_prefixes or ["/api/", "/admin/"]

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        session_key = getattr(request, "session", None)
        session_key = getattr(session_key, "session_key", None) if session_key else None
        path = request.path

        is_auth_path = any(path.startswith(p) for p in self.auth_prefixes)
        if is_auth_path and not session_key:
            return 25, "no_session_on_auth_path"

        if session_key:
            sess_entries = history.by_session
            uas = {e["ua"] for e in sess_entries}
            if len(uas) > 3:
                return 35, "session_ua_rotation"

        config = get_config()
        cache = caches[config["CACHE_BACKEND"]]
        prefix = config["CACHE_PREFIX"]
        ip = history.ip

        sess_count_key = f"{prefix}:sess_count:{ip}"
        if session_key:
            sessions_set_key = f"{prefix}:sess_set:{ip}"
            current_sessions = cache.get(sessions_set_key) or set()
            if isinstance(current_sessions, str):
                import json

                current_sessions = set(json.loads(current_sessions))
            current_sessions.add(session_key)
            cache.set(sessions_set_key, current_sessions, 300)
            cache.set(sess_count_key, len(current_sessions), 300)

            if len(current_sessions) > 10:
                return 30, "excessive_sessions_per_ip"

        return 0, None
