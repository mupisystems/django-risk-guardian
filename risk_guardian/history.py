from __future__ import annotations

import json
import time

from django.core.cache import caches

from risk_guardian.conf import get_config


class AccessHistory:
    def __init__(self, ip: str, session_key: str | None):
        self.ip = ip
        self.session_key = session_key
        self._config = get_config()
        self._cache = caches[self._config["CACHE_BACKEND"]]
        self._prefix = self._config["CACHE_PREFIX"]
        self._window = self._config["HISTORY_WINDOW_SECONDS"]
        self._max_requests = self._config["HISTORY_MAX_REQUESTS"]

    def _ip_key(self) -> str:
        return f"{self._prefix}:hist:ip:{self.ip}"

    def _session_key(self) -> str:
        return f"{self._prefix}:hist:sess:{self.session_key}"

    def _get_entries(self, key: str) -> list[dict]:
        raw = self._cache.get(key)
        if not raw:
            return []
        entries = json.loads(raw) if isinstance(raw, str) else raw
        cutoff = time.time() - self._window
        return [e for e in entries if e["ts"] >= cutoff]

    def _set_entries(self, key: str, entries: list[dict]) -> None:
        entries = entries[-self._max_requests:]
        ttl = self._window + 60
        self._cache.set(key, json.dumps(entries), ttl)

    def record(self, request_data: dict) -> AccessHistory:
        entry = {
            "ts": time.time(),
            "path": request_data["path"],
            "method": request_data["method"],
            "status": request_data["status"],
            "ua": request_data.get("user_agent", "")[:100],
            "duration_ms": request_data.get("duration_ms", 0.0),
        }

        ip_entries = self._get_entries(self._ip_key())
        ip_entries.append(entry)
        self._set_entries(self._ip_key(), ip_entries)

        if self.session_key:
            sess_entries = self._get_entries(self._session_key())
            sess_entries.append(entry)
            self._set_entries(self._session_key(), sess_entries)

        return self

    @property
    def by_ip(self) -> list[dict]:
        return self._get_entries(self._ip_key())

    @property
    def by_session(self) -> list[dict]:
        if not self.session_key:
            return []
        return self._get_entries(self._session_key())

    def requests_per_minute(self, entries: list | None = None) -> float:
        entries = entries if entries is not None else self.by_ip
        if len(entries) < 2:
            return 0.0
        timestamps = [e["ts"] for e in entries]
        span = max(timestamps) - min(timestamps)
        if span == 0:
            return float(len(entries))
        return len(entries) / (span / 60.0)

    def unique_paths(self, entries: list | None = None) -> set[str]:
        entries = entries if entries is not None else self.by_ip
        return {e["path"] for e in entries}

    def unique_user_agents(self, entries: list | None = None) -> set[str]:
        entries = entries if entries is not None else self.by_ip
        return {e["ua"] for e in entries}

    def error_rate(self, entries: list | None = None) -> float:
        entries = entries if entries is not None else self.by_ip
        if not entries:
            return 0.0
        errors = sum(1 for e in entries if e["status"] >= 400)
        return errors / len(entries)

    def avg_duration_ms(self, entries: list | None = None) -> float:
        entries = entries if entries is not None else self.by_ip
        if not entries:
            return 0.0
        return sum(e["duration_ms"] for e in entries) / len(entries)
