from __future__ import annotations

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.history import AccessHistory


class RateAnalyzer(BaseAnalyzer):
    def __init__(self, critical_rpm=120, high_rpm=60, medium_rpm=30, min_samples=5):
        self.critical_rpm = critical_rpm
        self.high_rpm = high_rpm
        self.medium_rpm = medium_rpm
        # A rate extrapolated from a couple of requests is noise: a form loaded
        # and submitted one second later reads as 120 requests per minute.
        self.min_samples = min_samples

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        entries = history.by_ip
        if len(entries) < self.min_samples:
            return 0, None
        rpm = history.requests_per_minute(entries)

        if rpm >= self.critical_rpm:
            return 50, "critical_rate"
        if rpm >= self.high_rpm:
            return 30, "high_rate"
        if rpm >= self.medium_rpm:
            return 15, "medium_rate"

        return 0, None
