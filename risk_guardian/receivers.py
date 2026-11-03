from __future__ import annotations

import json
import logging
from functools import wraps

from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver

from risk_guardian.analyzers.email import EmailAnalyzer
from risk_guardian.auth_tracking import LOGIN_FAILED, LOGIN_OK, SIGNUP, record_auth_event
from risk_guardian.signals import email_risk_assessed

try:
    from allauth.account.signals import user_signed_up
except ImportError:  # pragma: no cover - allauth is optional
    user_signed_up = None

logger = logging.getLogger("risk_guardian")
_analyzer = EmailAnalyzer()


def _never_raise(func):
    """Keep the receiver's failures out of the login or signup it listens to.

    These receivers run inside the project's authentication flow: an exception
    here would fail the user's login or signup. Like a failing analyzer, a
    failing receiver degrades detection, never the request.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            logger.exception(json.dumps({"event": "receiver_error", "receiver": func.__name__}))

    return wrapper


def _login_identifier(credentials) -> str:
    credentials = credentials or {}
    return credentials.get("username") or credentials.get("email") or credentials.get("login") or ""


def _user_identifier(user) -> str:
    get_username = getattr(user, "get_username", None)
    if callable(get_username):
        return get_username() or ""
    return getattr(user, "email", None) or ""


@receiver(user_logged_in)
@_never_raise
def record_successful_login(sender, request, user, **kwargs):
    record_auth_event(request, LOGIN_OK, _user_identifier(user))


@receiver(user_login_failed)
@_never_raise
def record_failed_login(sender, credentials, request=None, **kwargs):
    record_auth_event(request, LOGIN_FAILED, _login_identifier(credentials))


@_never_raise
def record_signup(sender, request, user, **kwargs):
    record_auth_event(request, SIGNUP, _user_identifier(user))


if user_signed_up is not None:  # pragma: no branch
    user_signed_up.connect(record_signup, dispatch_uid="risk_guardian_record_signup")


@receiver(user_logged_in)
@_never_raise
def assess_email_on_login(sender, request, user, **kwargs):
    risk = getattr(request, "risk", None)
    if not risk:
        return

    email = getattr(user, "email", None)
    if not email:
        return

    signals = _analyzer.evaluate(email)
    for delta, reason in signals:
        risk.add(delta, reason)

    if signals:
        email_risk_assessed.send(
            sender=sender,
            request=request,
            user=user,
            email=email,
            score=risk.score,
            reasons=[r for _, r in signals],
        )
        logger.info(
            json.dumps(
                {
                    "event": "email_risk_assessed",
                    "email_domain": email.rsplit("@", 1)[-1],
                    "score": risk.score,
                    "reasons": [r for _, r in signals],
                }
            )
        )


@receiver(user_login_failed)
@_never_raise
def track_failed_login(sender, credentials, request=None, **kwargs):
    risk = getattr(request, "risk", None) if request else None
    if not risk:
        return

    email = _login_identifier(credentials)
    if not email or "@" not in email:
        return

    signals = _analyzer.evaluate(email)
    for delta, reason in signals:
        risk.add(delta, reason)
