from __future__ import annotations

import time

import pytest

from risk_guardian.history import AccessHistory
from tests.factories import make_entry


class TestAccessHistory:
    def test_record_and_by_ip(self):
        history = AccessHistory("1.2.3.4", "sess1")
        history.record(make_entry())
        entries = history.by_ip
        assert len(entries) == 1
        assert entries[0]["path"] == "/api/test/"

    def test_record_and_by_session(self):
        history = AccessHistory("1.2.3.4", "sess1")
        history.record(make_entry())
        entries = history.by_session
        assert len(entries) == 1

    def test_by_session_empty_when_no_session_key(self):
        history = AccessHistory("1.2.3.4", None)
        history.record(make_entry())
        assert history.by_session == []

    def test_requests_per_minute_empty(self):
        history = AccessHistory("1.2.3.4", None)
        assert history.requests_per_minute() == 0.0

    def test_unique_paths(self):
        history = AccessHistory("1.2.3.4", None)
        history.record(make_entry(path="/a/"))
        history.record(make_entry(path="/b/"))
        history.record(make_entry(path="/a/"))
        assert history.unique_paths() == {"/a/", "/b/"}

    def test_unique_user_agents(self):
        history = AccessHistory("1.2.3.4", "s1")
        history.record(make_entry(user_agent="UA1"))
        history.record(make_entry(user_agent="UA2"))
        assert len(history.unique_user_agents()) == 2

    def test_error_rate(self):
        history = AccessHistory("1.2.3.4", None)
        history.record(make_entry(status=200))
        history.record(make_entry(status=404))
        assert history.error_rate() == 0.5

    def test_error_rate_empty(self):
        history = AccessHistory("1.2.3.4", None)
        assert history.error_rate() == 0.0

    def test_avg_duration_ms(self):
        history = AccessHistory("1.2.3.4", None)
        history.record(make_entry(duration_ms=100.0))
        history.record(make_entry(duration_ms=200.0))
        assert history.avg_duration_ms() == pytest.approx(150.0, rel=0.1)

    def test_max_requests_trim(self):
        history = AccessHistory("1.2.3.4", None)
        for i in range(110):
            history.record(make_entry(path=f"/p/{i}/"))
        entries = history.by_ip
        assert len(entries) <= 100

    def test_window_expiry(self):
        history = AccessHistory("1.2.3.4", None)
        # Manually insert an old entry
        import json

        old_entry = {
            "ts": time.time() - 600,  # 10 min ago, outside 5-min window
            "path": "/old/",
            "method": "GET",
            "status": 200,
            "ua": "test",
            "duration_ms": 10.0,
        }
        key = history._ip_key()
        history._cache.set(key, json.dumps([old_entry]), 400)
        entries = history.by_ip
        assert len(entries) == 0
