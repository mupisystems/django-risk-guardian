from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from risk_guardian.analyzers.rate import RateAnalyzer
from risk_guardian.analyzers.user_agent import UserAgentAnalyzer
from risk_guardian.analyzers.session import SessionAnalyzer
from risk_guardian.analyzers.pattern import PatternAnalyzer
from risk_guardian.analyzers.timing import TimingAnalyzer
from tests.factories import make_request, make_history, make_entry


# ── RateAnalyzer ──


class TestRateAnalyzer:
    def test_no_signal_low_rate(self):
        request = make_request()
        history = make_history()
        analyzer = RateAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None

    def test_medium_rate(self):
        request = make_request()
        history = make_history()
        for _ in range(35):
            history.record(make_entry())
        with patch.object(history, "requests_per_minute", return_value=35.0):
            analyzer = RateAnalyzer()
            delta, reason = analyzer.analyze(request, history)
            assert delta == 15
            assert reason == "medium_rate"

    def test_high_rate(self):
        request = make_request()
        history = make_history()
        with patch.object(history, "requests_per_minute", return_value=65.0):
            analyzer = RateAnalyzer()
            delta, reason = analyzer.analyze(request, history)
            assert delta == 30
            assert reason == "high_rate"

    def test_critical_rate(self):
        request = make_request()
        history = make_history()
        with patch.object(history, "requests_per_minute", return_value=125.0):
            analyzer = RateAnalyzer()
            delta, reason = analyzer.analyze(request, history)
            assert delta == 50
            assert reason == "critical_rate"


# ── UserAgentAnalyzer ──


class TestUserAgentAnalyzer:
    def test_no_signal_normal_ua(self):
        request = make_request()
        history = make_history()
        analyzer = UserAgentAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None

    def test_missing_ua(self):
        request = make_request(user_agent=None)
        # Remove the key entirely
        request.META.pop("HTTP_USER_AGENT", None)
        history = make_history()
        analyzer = UserAgentAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 30
        assert reason == "missing_ua"

    def test_bot_ua_curl(self):
        request = make_request(user_agent="curl/7.68.0")
        history = make_history()
        analyzer = UserAgentAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 40
        assert reason == "bot_ua:curl"

    def test_bot_ua_python_requests(self):
        request = make_request(user_agent="python-requests/2.28.0")
        history = make_history()
        analyzer = UserAgentAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 40
        assert reason == "bot_ua:python-requests"

    def test_outdated_browser(self):
        request = make_request(
            user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/90.0.4430.93 Safari/537.36"
        )
        history = make_history()
        analyzer = UserAgentAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 20
        assert reason == "outdated_browser"

    def test_current_browser_no_signal(self):
        request = make_request(
            user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/125.0.0.0 Safari/537.36"
        )
        history = make_history()
        analyzer = UserAgentAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None


# ── SessionAnalyzer ──


class TestSessionAnalyzer:
    def test_no_signal(self):
        request = make_request(path="/public/page/")
        history = make_history()
        analyzer = SessionAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None

    def test_no_session_on_auth_path(self):
        request = make_request(path="/api/data/", session_key=None)
        request.session = None
        history = make_history()
        analyzer = SessionAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 25
        assert reason == "no_session_on_auth_path"

    def test_session_ua_rotation(self):
        request = make_request()
        history = make_history()
        # Record entries with >3 different user agents in the session
        for i in range(5):
            history.record(make_entry(user_agent=f"UA-{i}"))
        analyzer = SessionAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 35
        assert reason == "session_ua_rotation"


# ── PatternAnalyzer ──


class TestPatternAnalyzer:
    def test_no_signal(self):
        request = make_request(path="/api/data/")
        history = make_history()
        analyzer = PatternAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None

    def test_scan_attempt_env(self):
        request = make_request(path="/.env")
        history = make_history()
        analyzer = PatternAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 60
        assert reason == "scan_attempt:/.env"

    def test_scan_attempt_wp_admin(self):
        request = make_request(path="/wp-admin/login.php")
        history = make_history()
        analyzer = PatternAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 60
        assert reason == "scan_attempt:/wp-admin"

    def test_high_error_rate(self):
        request = make_request(path="/api/data/")
        history = make_history()
        for _ in range(10):
            history.record(make_entry(status=404))
        analyzer = PatternAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 30
        assert reason == "high_error_rate"

    def test_excessive_path_diversity(self):
        request = make_request(path="/api/data/")
        history = make_history()
        for i in range(45):
            history.record(make_entry(path=f"/path/{i}/"))
        analyzer = PatternAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 25
        assert reason == "excessive_path_diversity"


# ── TimingAnalyzer ──


class TestTimingAnalyzer:
    def test_no_signal_insufficient_entries(self):
        request = make_request()
        history = make_history()
        # Only 3 entries, need at least 5
        for _ in range(3):
            history.record(make_entry())
        analyzer = TimingAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None

    def test_robotic_timing(self):
        request = make_request()
        history = make_history()
        # Manually set up entries with very regular intervals
        ip_key = history._ip_key()
        import json
        now = time.time()
        entries = [
            {"ts": now + i * 1.0, "path": "/api/", "method": "GET", "status": 200, "ua": "bot", "duration_ms": 10.0}
            for i in range(10)
        ]
        history._set_entries(ip_key, entries)
        analyzer = TimingAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 30
        assert reason == "robotic_timing"

    def test_normal_timing_no_signal(self):
        request = make_request()
        history = make_history()
        ip_key = history._ip_key()
        import json
        import random
        now = time.time()
        entries = [
            {"ts": now + i * random.uniform(0.5, 5.0), "path": "/api/", "method": "GET", "status": 200, "ua": "normal", "duration_ms": 10.0}
            for i in range(10)
        ]
        # Make sure intervals are very irregular
        entries[0]["ts"] = now
        entries[1]["ts"] = now + 0.3
        entries[2]["ts"] = now + 2.5
        entries[3]["ts"] = now + 3.0
        entries[4]["ts"] = now + 8.0
        entries[5]["ts"] = now + 8.1
        entries[6]["ts"] = now + 12.0
        entries[7]["ts"] = now + 15.5
        entries[8]["ts"] = now + 16.0
        entries[9]["ts"] = now + 25.0
        history._set_entries(ip_key, entries)
        analyzer = TimingAnalyzer()
        delta, reason = analyzer.analyze(request, history)
        assert delta == 0
        assert reason is None
