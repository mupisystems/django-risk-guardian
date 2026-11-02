from __future__ import annotations

import hashlib
import hmac
import json
import time

from django.conf import settings
from django.core.cache import caches

from risk_guardian.conf import get_config
from risk_guardian.network import get_client_ip, ip_in

LOGIN_OK = "ok"
LOGIN_FAILED = "fail"
SIGNUP = "signup"


class AuthTracker:
    """Per-IP record of the accounts that logged in, failed to log in or signed up.

    Credential stuffing tries one or two passwords per account, so per-account
    lockouts never fire. The signal is the number of *distinct* accounts touched
    from one IP inside ``AUTH_WINDOW_SECONDS``.

    Accounts are stored as a keyed hash of the normalized identifier, never as
    the e-mail or username itself: the cache holds no personal data.
    """

    def __init__(self, ip: str, config=None):
        self.ip = ip
        self._config = config or get_config()
        self._cache = caches[self._config["CACHE_BACKEND"]]
        self._prefix = self._config["CACHE_PREFIX"]
        self._window = self._config["AUTH_WINDOW_SECONDS"]

    @staticmethod
    def account_id(identifier: str) -> str:
        normalized = (identifier or "").strip().lower().encode()
        return hmac.new(settings.SECRET_KEY.encode(), normalized, hashlib.sha256).hexdigest()[:16]

    def _key(self, kind: str) -> str:
        return f"{self._prefix}:auth:{kind}:{self.ip}"

    def _entries(self, kind: str) -> dict[str, float]:
        raw = self._cache.get(self._key(kind))
        if not raw:
            return {}
        entries = json.loads(raw) if isinstance(raw, str) else raw
        cutoff = time.time() - self._window
        return {account: ts for account, ts in entries.items() if ts >= cutoff}

    def record(self, kind: str, identifier: str) -> None:
        if not identifier:
            return
        entries = self._entries(kind)
        entries[self.account_id(identifier)] = time.time()
        self._cache.set(self._key(kind), json.dumps(entries), self._window + 60)

    def counts(self) -> dict[str, int]:
        ok = self._entries(LOGIN_OK)
        failed = self._entries(LOGIN_FAILED)
        return {
            "accounts": len(set(ok) | set(failed)),
            "failed_accounts": len(failed),
            "signups": len(self._entries(SIGNUP)),
        }


def evaluate_auth_counts(counts: dict[str, int], config=None) -> tuple[int, str | None]:
    """Turn the per-IP counts into a single (delta, reason), the strongest signal wins.

    Failures weigh more than successes: an office where ten people log in from
    one IP rarely mistypes the password of five different accounts, while a
    stolen-credentials list fails on roughly half of them.
    """
    config = config or get_config()
    candidates = [(0, None)]

    if counts["failed_accounts"] >= config["AUTH_FAILED_ACCOUNTS_BLOCK"]:
        candidates.append((80, "credential_stuffing"))
    if counts["failed_accounts"] >= config["AUTH_FAILED_ACCOUNTS_CHALLENGE"]:
        candidates.append((50, "failed_logins_many_accounts"))
    if counts["accounts"] >= config["AUTH_ACCOUNTS_CHALLENGE"]:
        candidates.append((50, "logins_many_accounts"))
    elif counts["accounts"] >= config["AUTH_ACCOUNTS_MONITOR"]:
        candidates.append((20, "logins_several_accounts"))
    if counts["signups"] >= config["AUTH_SIGNUPS_CHALLENGE"]:
        candidates.append((50, "signup_velocity"))

    return max(candidates, key=lambda candidate: candidate[0])


def record_auth_event(request, kind: str, identifier: str) -> None:
    """Record a login (``LOGIN_OK``/``LOGIN_FAILED``) or ``SIGNUP`` for the request IP.

    Called by the bundled receivers; projects with a custom signup or login
    flow can call it directly. The signal is also added to ``request.risk``
    so the view that performed the login can react in the same request.
    """
    if request is None or not identifier:
        return
    config = get_config()
    if not config["ENABLED"]:
        return
    ip = get_client_ip(request, config)
    if ip_in(ip, config["ALLOWLIST_IPS"]):
        return

    tracker = AuthTracker(ip, config)
    tracker.record(kind, identifier)

    risk = getattr(request, "risk", None)
    if risk is not None:
        delta, reason = evaluate_auth_counts(tracker.counts(), config)
        if reason and reason not in risk.reasons:
            risk.add(delta, reason)
