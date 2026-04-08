from __future__ import annotations

import time
from unittest.mock import MagicMock

from django.http import HttpRequest

from risk_guardian.history import AccessHistory


def make_request(
    ip="1.2.3.4",
    path="/api/test/",
    method="GET",
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    session_key="abc123",
) -> HttpRequest:
    request = HttpRequest()
    request.method = method
    request.path = path
    request.META["REMOTE_ADDR"] = ip
    if user_agent is not None:
        request.META["HTTP_USER_AGENT"] = user_agent
    if session_key:
        session = MagicMock()
        session.session_key = session_key
        request.session = session
    else:
        request.session = None
    return request


def make_history(
    ip="1.2.3.4",
    session_key="abc123",
    entries: list[dict] | None = None,
) -> AccessHistory:
    history = AccessHistory(ip, session_key)
    if entries:
        for entry in entries:
            history.record(entry)
    return history


def make_entry(
    path="/api/test/",
    method="GET",
    status=200,
    user_agent="Mozilla/5.0",
    duration_ms=50.0,
    ts_offset=0.0,
) -> dict:
    return {
        "path": path,
        "method": method,
        "status": status,
        "user_agent": user_agent,
        "duration_ms": duration_ms,
    }
