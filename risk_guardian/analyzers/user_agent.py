from __future__ import annotations

import re

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.history import AccessHistory

BOT_PATTERNS = [
    "python-requests",
    "curl",
    "wget",
    "scrapy",
    "go-http-client",
    "java/",
    "libwww",
]


class UserAgentAnalyzer(BaseAnalyzer):
    def __init__(self, min_chrome_version=120):
        self.min_chrome_version = min_chrome_version

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        ua = request.META.get("HTTP_USER_AGENT", "")

        if not ua:
            return 30, "missing_ua"

        ua_lower = ua.lower()
        for pattern in BOT_PATTERNS:
            if pattern in ua_lower:
                return 40, f"bot_ua:{pattern}"

        match = re.search(r"Chrome/(\d+)", ua)
        if match:
            version = int(match.group(1))
            if version < self.min_chrome_version:
                return 20, "outdated_browser"

        return 0, None
