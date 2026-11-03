"""The receivers run inside the project's login and signup: they must never break them."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory

from risk_guardian.auth_tracking import AuthTracker
from risk_guardian.receivers import record_signup

IP = "203.0.113.9"


def _request():
    request = RequestFactory().post("/accounts/signup/")
    request.META["REMOTE_ADDR"] = IP
    return request


def _receiver_errors(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if "receiver_error" in r.getMessage()]


def test_user_without_get_username_is_identified_by_email():
    record_signup(sender=None, request=_request(), user=SimpleNamespace(email="a@example.com"))
    assert AuthTracker(IP).counts()["signups"] == 1


def test_fake_user_and_request_do_not_raise(caplog):
    # Projects send allauth's user_signed_up with stand-ins in their own tests.
    fake_request = SimpleNamespace(session={})
    record_signup(sender=None, request=fake_request, user=SimpleNamespace(selected_organization_id=1))
    record_signup(sender=None, request=fake_request, user=SimpleNamespace(email="a@example.com"))
    assert _receiver_errors(caplog) == [{"event": "receiver_error", "receiver": "record_signup"}]


@pytest.mark.django_db
def test_failing_tracking_does_not_break_authentication(caplog):
    get_user_model().objects.create_user("alice", password="right")  # noqa: S106
    request = _request()
    request.session = SessionStore()
    request.user = MagicMock()

    with patch("risk_guardian.receivers.record_auth_event", side_effect=RuntimeError("cache down")):
        assert authenticate(request, username="alice", password="wrong") is None  # noqa: S106
        user = authenticate(request, username="alice", password="right")  # noqa: S106
        login(request, user)

    assert request.session["_auth_user_id"] == str(user.pk)
    receivers = {error["receiver"] for error in _receiver_errors(caplog)}
    assert receivers == {"record_failed_login", "record_successful_login"}


def test_receiver_error_is_logged_at_error_level(caplog):
    caplog.set_level(logging.ERROR, logger="risk_guardian")
    record_signup(sender=None, request=SimpleNamespace(), user=SimpleNamespace(email="a@example.com"))
    assert caplog.records[-1].levelno == logging.ERROR
