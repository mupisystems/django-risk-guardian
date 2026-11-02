from __future__ import annotations

from risk_guardian.analyzers.base import BaseAnalyzer
from risk_guardian.conf import get_config
from risk_guardian.history import AccessHistory
from risk_guardian.network import ip_in

# Cloudflare's code for traffic from the Tor network.
TOR_COUNTRY_CODE = "T1"
UNKNOWN_COUNTRY_CODES = {"", "XX", "--"}


class GeoAnalyzer(BaseAnalyzer):
    """Scores requests by the country the web server or the CDN resolved.

    The analyzer does no lookup of its own: it reads the country code from
    ``GEO_COUNTRY_META_KEY``. The safest source is a variable set by the web
    server, such as nginx's geoip2 module passing ``GEOIP_COUNTRY_CODE`` to the
    application: keys without the ``HTTP_`` prefix cannot come from the client.
    A header such as Cloudflare's ``HTTP_CF_IPCOUNTRY`` can, so it is read only
    when the request comes from one of ``TRUSTED_PROXIES``.

    Without ``GEO_COUNTRY_META_KEY`` the analyzer does nothing.
    """

    def __init__(self):
        config = get_config()
        self.meta_key = config["GEO_COUNTRY_META_KEY"]
        self.allowed = {code.upper() for code in config["GEO_ALLOWED_COUNTRIES"]}
        self.unexpected_score = config["GEO_UNEXPECTED_COUNTRY_SCORE"]
        self.tor_score = config["GEO_TOR_SCORE"]
        self.trusted_proxies = config["TRUSTED_PROXIES"]

    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]:
        if not self.meta_key:
            return 0, None
        if self.meta_key.startswith("HTTP_") and not ip_in(request.META.get("REMOTE_ADDR", ""), self.trusted_proxies):
            return 0, None

        country = (request.META.get(self.meta_key) or "").strip().upper()
        if country == TOR_COUNTRY_CODE:
            return self.tor_score, "tor_exit"
        if country in UNKNOWN_COUNTRY_CODES or not self.allowed or country in self.allowed:
            return 0, None
        return self.unexpected_score, f"unexpected_country:{country}"
