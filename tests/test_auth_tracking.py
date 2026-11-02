from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.sessions.backends.db import SessionStore
from django.core.cache import caches
from django.test import RequestFactory

from risk_guardian.analyzers.auth import AuthAnalyzer
from risk_guardian.assessment import RiskAssessment
from risk_guardian.auth_tracking import (
    LOGIN_FAILED,
    LOGIN_OK,
    SIGNUP,
    AuthTracker,
    evaluate_auth_counts,
    record_auth_event,
)
from risk_guardian.conf import get_config
from risk_guardian.receivers import record_signup
from tests.factories import make_history, make_request

IP = "203.0.113.9"


def _request(ip=IP, with_risk=True):
    request = RequestFactory().post("/accounts/login/")
    request.META["REMOTE_ADDR"] = ip
    if with_risk:
        request.risk = RiskAssessment()
    return request


def _counts(accounts=0, failed_accounts=0, signups=0):
    return {"accounts": accounts, "failed_accounts": failed_accounts, "signups": signups}


class TestAuthTracker:
    def test_counts_distinct_accounts_across_successes_and_failures(self):
        tracker = AuthTracker(IP)
        tracker.record(LOGIN_FAILED, "a@example.com")
        tracker.record(LOGIN_FAILED, "A@Example.com ")  # same account, normalized
        tracker.record(LOGIN_OK, "a@example.com")
        tracker.record(LOGIN_OK, "b@example.com")
        tracker.record(SIGNUP, "c@example.com")
        assert tracker.counts() == {"accounts": 2, "failed_accounts": 1, "signups": 1}

    def test_ips_are_tracked_separately(self):
        AuthTracker(IP).record(LOGIN_FAILED, "a@example.com")
        assert AuthTracker("198.51.100.1").counts()["failed_accounts"] == 0

    def test_entries_expire_after_window(self, monkeypatch):
        tracker = AuthTracker(IP)
        tracker.record(LOGIN_FAILED, "a@example.com")
        later = time.time() + get_config()["AUTH_WINDOW_SECONDS"] + 1
        monkeypatch.setattr(time, "time", lambda: later)
        assert AuthTracker(IP).counts()["failed_accounts"] == 0

    def test_cache_stores_no_personal_data(self):
        AuthTracker(IP).record(LOGIN_FAILED, "victim@example.com")
        config = get_config()
        raw = caches[config["CACHE_BACKEND"]].get(f"{config['CACHE_PREFIX']}:auth:{LOGIN_FAILED}:{IP}")
        assert "victim" not in raw
        assert AuthTracker.account_id("victim@example.com") in raw

    def test_empty_identifier_is_ignored(self):
        tracker = AuthTracker(IP)
        tracker.record(LOGIN_FAILED, "")
        assert tracker.counts()["failed_accounts"] == 0


class TestEvaluateAuthCounts:
    @pytest.mark.parametrize(
        ("counts", "expected"),
        [
            (_counts(accounts=2), (0, None)),
            (_counts(accounts=3), (20, "logins_several_accounts")),
            (_counts(accounts=5), (50, "logins_many_accounts")),
            (_counts(accounts=3, failed_accounts=3), (50, "failed_logins_many_accounts")),
            (_counts(accounts=5, failed_accounts=5), (80, "credential_stuffing")),
            (_counts(signups=3), (50, "signup_velocity")),
            (_counts(accounts=10), (50, "logins_many_accounts")),
        ],
    )
    def test_thresholds(self, counts, expected):
        assert evaluate_auth_counts(counts) == expected

    def test_thresholds_are_configurable(self, settings):
        settings.RISK_GUARDIAN = {"AUTH_FAILED_ACCOUNTS_BLOCK": 2}
        assert evaluate_auth_counts(_counts(accounts=2, failed_accounts=2)) == (80, "credential_stuffing")


class TestRecordAuthEvent:
    def test_records_and_raises_request_risk_once(self):
        request = _request()
        for email in ("a@example.com", "b@example.com", "c@example.com"):
            record_auth_event(request, LOGIN_FAILED, email)
        assert AuthTracker(IP).counts()["failed_accounts"] == 3
        assert request.risk.reasons.count("failed_logins_many_accounts") == 1
        assert request.risk.score == 50

    def test_works_without_request_risk(self):
        record_auth_event(_request(with_risk=False), LOGIN_FAILED, "a@example.com")
        assert AuthTracker(IP).counts()["failed_accounts"] == 1

    def test_noop_without_request_or_identifier(self):
        record_auth_event(None, LOGIN_FAILED, "a@example.com")
        record_auth_event(_request(), LOGIN_FAILED, "")
        assert AuthTracker(IP).counts()["failed_accounts"] == 0

    def test_noop_when_disabled(self, settings):
        settings.RISK_GUARDIAN = {"ENABLED": False}
        record_auth_event(_request(), LOGIN_FAILED, "a@example.com")
        assert AuthTracker(IP).counts()["failed_accounts"] == 0

    def test_noop_for_allowlisted_ip(self, settings):
        settings.RISK_GUARDIAN = {"ALLOWLIST_IPS": ["203.0.113.0/24"]}
        record_auth_event(_request(), LOGIN_FAILED, "a@example.com")
        assert AuthTracker(IP).counts()["failed_accounts"] == 0


@pytest.mark.django_db
class TestReceivers:
    def test_failed_authenticate_is_recorded(self):
        get_user_model().objects.create_user("alice", password="right")  # noqa: S106
        request = _request()
        assert authenticate(request, username="alice", password="wrong") is None  # noqa: S106
        assert AuthTracker(IP).counts() == {"accounts": 1, "failed_accounts": 1, "signups": 0}

    def test_successful_login_is_recorded(self):
        user = get_user_model().objects.create_user("bob", password="right")  # noqa: S106
        request = _request()
        request.session = SessionStore()
        request.user = MagicMock()
        login(request, authenticate(request, username="bob", password="right"))  # noqa: S106
        assert user.is_authenticated
        assert AuthTracker(IP).counts() == {"accounts": 1, "failed_accounts": 0, "signups": 0}

    def test_signup_receiver_records_signup(self):
        user = get_user_model().objects.create_user("carol", password="x")  # noqa: S106
        record_signup(sender=None, request=_request(), user=user)
        assert AuthTracker(IP).counts()["signups"] == 1


class TestAuthAnalyzer:
    def test_reads_counts_recorded_for_the_ip(self):
        for email in ("a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com"):
            AuthTracker(IP).record(LOGIN_FAILED, email)
        delta, reason = AuthAnalyzer().analyze(make_request(ip=IP), make_history(ip=IP))
        assert (delta, reason) == (80, "credential_stuffing")

    def test_no_signal_for_clean_ip(self):
        assert AuthAnalyzer().analyze(make_request(ip=IP), make_history(ip=IP)) == (0, None)
