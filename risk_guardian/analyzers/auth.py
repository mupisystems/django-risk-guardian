from __future__ import annotations

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.auth_tracking import AuthTracker, evaluate_auth_counts
from risk_guardian.conf import get_config
from risk_guardian.history import AccessHistory


class AuthAnalyzer(BaseAnalyzer):
    """Scores an IP by the logins and signups recorded for it by the receivers.

    The login itself runs inside the view, after the middleware has decided.
    The receivers record it and raise ``request.risk`` for that request; this
    analyzer applies the accumulated signal to every following request from
    the same IP, which is where the challenge or the block lands.
    """

    def __init__(self):
        self._config = get_config()

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        counts = AuthTracker(history.ip, self._config).counts()
        return evaluate_auth_counts(counts, self._config)
