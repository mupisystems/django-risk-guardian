from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

import pytest
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory

from risk_guardian.conf import get_config
from risk_guardian.middleware import RiskGuardianMiddleware
from risk_guardian.signals import challenge_required, ip_blocked

IP = "203.0.113.9"


def _view(request):
    return HttpResponse("OK")


def _middleware(score):
    middleware = RiskGuardianMiddleware(_view)
    first, *others = middleware._analyzers
    first.analyze = MagicMock(return_value=(score, "test_signal"))
    for analyzer in others:
        analyzer.analyze = MagicMock(return_value=(0, None))
    return middleware


def _request(path="/accounts/login/?next=/secret-token", **meta):
    request = RequestFactory().post(path, **meta)
    request.META["REMOTE_ADDR"] = IP
    request.session = MagicMock(session_key="sess")
    return request


def _events(caplog):
    return [json.loads(record.getMessage()) for record in caplog.records if record.name == "risk_guardian"]


def _blocked_flag():
    config = get_config()
    return caches[config["CACHE_BACKEND"]].get(f"{config['CACHE_PREFIX']}:blocked:{IP}")


@pytest.fixture
def observe(settings):
    settings.RISK_GUARDIAN = {"MODE": "observe"}


@pytest.fixture
def received():
    calls = []

    def listener(sender, **kwargs):
        calls.append(kwargs)

    ip_blocked.connect(listener)
    challenge_required.connect(listener)
    yield calls
    ip_blocked.disconnect(listener)
    challenge_required.disconnect(listener)


@pytest.mark.parametrize(
    ("score", "decision"),
    [(0, "allow"), (20, "monitor"), (50, "challenge"), (79, "challenge")],
)
def test_decision_is_set_in_enforce_mode(score, decision):
    request = _request()
    _middleware(score)(request)
    assert request.risk.decision == decision
    assert request.risk.as_dict()["decision"] == decision


def test_invalid_mode_is_rejected(settings):
    settings.RISK_GUARDIAN = {"MODE": "monitor"}
    with pytest.raises(ImproperlyConfigured):
        RiskGuardianMiddleware(_view)


@pytest.mark.usefixtures("observe")
class TestObserveMode:
    def test_block_decision_lets_the_request_through(self, caplog, received):
        caplog.set_level(logging.INFO, logger="risk_guardian")
        request = _request()
        response = _middleware(90)(request)

        assert response.status_code == 200
        assert request.risk.decision == "block"
        assert request.risk.blocked is False
        assert not _blocked_flag()
        assert received == []
        events = {event["event"]: event for event in _events(caplog)}
        assert events["ip_blocked"]["mode"] == "observe"
        assert events["ip_blocked"]["decision"] == "block"

    def test_challenge_decision_does_not_flag_the_view(self, caplog, received):
        caplog.set_level(logging.INFO, logger="risk_guardian")
        request = _request()
        _middleware(60)(request)

        assert request.risk.decision == "challenge"
        assert request.risk.challenged is False
        assert received == []
        assert "challenge_required" in {event["event"] for event in _events(caplog)}

    def test_existing_block_is_ignored(self):
        config = get_config()
        caches[config["CACHE_BACKEND"]].set(f"{config['CACHE_PREFIX']}:blocked:{IP}", 1, 60)
        response = _middleware(0)(_request())
        assert response.status_code == 200


def test_enforce_mode_still_blocks(caplog, received):
    caplog.set_level(logging.INFO, logger="risk_guardian")
    response = _middleware(90)(_request())
    assert response.status_code == 429
    assert _blocked_flag()
    assert len(received) == 1
    assert _events(caplog)[0]["mode"] == "enforce"


def test_log_event_carries_request_context(caplog):
    caplog.set_level(logging.INFO, logger="risk_guardian")
    _middleware(30)(_request(HTTP_X_REQUEST_ID="abc123"))
    (event,) = [e for e in _events(caplog) if e["event"] == "risk_assessed"]
    assert event["method"] == "POST"
    assert event["path"] == "/accounts/login/"  # no query string: it may carry tokens
    assert event["request_id"] == "abc123"
    assert event["reasons"] == ["test_signal"]


def test_request_id_attribute_wins_over_header(caplog):
    caplog.set_level(logging.INFO, logger="risk_guardian")
    request = _request(HTTP_X_REQUEST_ID="from-header")
    request.request_id = "from-attribute"
    _middleware(30)(request)
    assert _events(caplog)[0]["request_id"] == "from-attribute"
