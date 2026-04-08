from __future__ import annotations

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.history import AccessHistory


class RateAnalyzer(BaseAnalyzer):
    def __init__(self, critical_rpm=120, high_rpm=60, medium_rpm=30):
        self.critical_rpm = critical_rpm
        self.high_rpm = high_rpm
        self.medium_rpm = medium_rpm

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        rpm = history.requests_per_minute()

        if rpm >= self.critical_rpm:
            return 50, "critical_rate"
        if rpm >= self.high_rpm:
            return 30, "high_rate"
        if rpm >= self.medium_rpm:
            return 15, "medium_rate"

        return 0, None
