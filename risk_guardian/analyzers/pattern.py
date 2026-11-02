from __future__ import annotations

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.conf import get_config
from risk_guardian.history import AccessHistory

SCAN_PATHS = [
    "/.env",
    "/wp-admin",
    "/phpmyadmin",
    "/.git",
    "/.aws",
    "/config.php",
    "/.svn",
    "/django-admin",
    "/backoffice",
    "/adminer",
    "/administrator",
    "/_ignition",
    "/actuator",
    "/xmlrpc.php",
    "/vendor/phpunit",
]


class PatternAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.scan_paths = [*SCAN_PATHS, *get_config()["EXTRA_SCAN_PATHS"]]

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        path = request.path

        for scan_path in self.scan_paths:
            if path.startswith(scan_path):
                return 60, f"scan_attempt:{scan_path}"

        ip_entries = history.by_ip

        if ip_entries:
            error_rate = history.error_rate(ip_entries)
            if error_rate > 0.5:
                return 30, "high_error_rate"

        unique = history.unique_paths(ip_entries)
        if len(unique) > 40:
            return 25, "excessive_path_diversity"

        return 0, None
