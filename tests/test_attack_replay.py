"""Replays of typical traffic patterns through the full middleware stack.

``CREDENTIAL_STUFFING`` is a typical credential stuffing run: a list of stolen
e-mail/password pairs tried against a login page with a bare ``Mozilla/5.0``
user agent, one or two attempts per account, at an irregular cadence (seconds
from the first attempt), with about half of the passwords already changed by
their owners.
"""

from __future__ import annotations

import time

import pytest
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory

from risk_guardian.middleware import RiskGuardianMiddleware

ATTACKER_IP = "203.0.113.9"
OFFICE_IP = "198.51.100.20"
BARE_UA = "Mozilla/5.0"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36"

# (seconds from start, account, whether the stolen password still works)
CREDENTIAL_STUFFING = [
    (0, "stale01", False),
    (5, "stale02", False),
    (7, "victim01", True),
    (13, "stale03", False),
    (15, "victim02", True),
    (21, "stale04", False),
    (27, "stale05", False),
    (29, "victim03", True),
    (58, "victim01", True),
    (998, "stale06", False),
    (1001, "victim04", True),
    (1006, "stale07", False),
    (1009, "victim05", True),
    (1013, "victim06", True),
    (1018, "stale08", False),
    (1029, "victim04", True),
    (1074, "stale06", False),
    (1079, "stale08", False),
    (1083, "victim06", True),
]


def _login_view(request):
    if request.method == "GET":
        return HttpResponse("login form")
    user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
    if user is None:
        return HttpResponse("login form", status=200)
    request.user = AnonymousUser()
    login(request, user)
    return HttpResponse(status=302)


class Clock:
    def __init__(self):
        self.start = time.time()
        self.now = self.start

    def at(self, seconds):
        self.now = self.start + seconds

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(time, "time", clock)
    return clock


@pytest.fixture
def stack():
    # Same order as in a real project: sessions first, then Risk Guardian.
    return SessionMiddleware(RiskGuardianMiddleware(_login_view))


def _send(stack, ip, ua, method="get", data=None):
    factory = RequestFactory()
    request = getattr(factory, method)("/accounts/login/", data=data or {})
    request.META["REMOTE_ADDR"] = ip
    request.META["HTTP_USER_AGENT"] = ua
    return request, stack(request)


def _create_users(usernames):
    for username in usernames:
        get_user_model().objects.create_user(username, password="right")  # noqa: S106


@pytest.mark.django_db
def test_credential_stuffing_is_blocked_after_the_third_failed_account(stack, clock):
    _create_users({account for _, account, _ in CREDENTIAL_STUFFING})

    compromised, first_block = [], None
    for seconds, account, password_works in CREDENTIAL_STUFFING:
        clock.at(seconds - 1)
        _send(stack, ATTACKER_IP, BARE_UA)  # the attacker loads the form before each POST
        clock.at(seconds)
        password = "right" if password_works else "stolen-but-changed"
        _, response = _send(stack, ATTACKER_IP, BARE_UA, "post", {"username": account, "password": password})
        if response.status_code == 429:
            first_block = seconds if first_block is None else first_block
        elif response.status_code == 302 and account not in compromised:
            compromised.append(account)

    # stale03 is the third distinct failed account (t=13): the next request is blocked.
    assert first_block == 15
    assert compromised == ["victim01"]


@pytest.mark.django_db
def test_office_sharing_one_ip_is_challenged_but_never_blocked(stack, clock):
    staff = [f"staff{i:02d}" for i in range(10)]
    _create_users(staff)

    responses = []
    for minute, username in enumerate(staff):
        clock.at(minute * 180)
        _send(stack, OFFICE_IP, BROWSER_UA)
        clock.at(minute * 180 + 20)
        if minute == 4:  # one typo, then the right password
            _send(stack, OFFICE_IP, BROWSER_UA, "post", {"username": username, "password": "typo"})
            clock.at(minute * 180 + 40)
        request, response = _send(stack, OFFICE_IP, BROWSER_UA, "post", {"username": username, "password": "right"})
        responses.append(response.status_code)

    assert 429 not in responses
    assert all(code == 302 for code in responses)
    # From the fifth account on, the view is told to challenge (e.g. e-mail code).
    assert request.risk.challenged
    assert "logins_many_accounts" in request.risk.reasons


@pytest.mark.django_db
def test_signup_bot_is_challenged(stack, clock):
    from risk_guardian.auth_tracking import SIGNUP, record_auth_event

    for i, email in enumerate(["signup1@example.com", "signup2@example.com", "signup3@example.com"]):
        clock.at(i * 600)
        request, _ = _send(stack, ATTACKER_IP, BROWSER_UA)
        record_auth_event(request, SIGNUP, email)

    clock.at(1900)
    request, response = _send(stack, ATTACKER_IP, BROWSER_UA)
    assert response.status_code == 200
    assert request.risk.challenged
    assert "signup_velocity" in request.risk.reasons
