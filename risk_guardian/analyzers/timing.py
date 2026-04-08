from __future__ import annotations

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.history import AccessHistory


class TimingAnalyzer(BaseAnalyzer):
    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        entries = history.by_ip
        if len(entries) < 5:
            return 0, None

        timestamps = sorted(e["ts"] for e in entries)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return 30, "robotic_timing"

        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        cv = variance / mean

        if cv < 0.05:
            return 30, "robotic_timing"

        return 0, None
