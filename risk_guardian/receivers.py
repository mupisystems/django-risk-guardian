from __future__ import annotations

import json
import logging

from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver

from risk_guardian.analyzers.email import EmailAnalyzer
from risk_guardian.signals import email_risk_assessed

logger = logging.getLogger("risk_guardian")
_analyzer = EmailAnalyzer()


@receiver(user_logged_in)
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
def track_failed_login(sender, credentials, request, **kwargs):
    risk = getattr(request, "risk", None) if request else None
    if not risk:
        return

    email = credentials.get("username", "") or credentials.get("email", "")
    if not email or "@" not in email:
        return

    signals = _analyzer.evaluate(email)
    for delta, reason in signals:
        risk.add(delta, reason)
