from __future__ import annotations

import pytest

from risk_guardian.analyzers.geo import GeoAnalyzer
from tests.factories import make_history, make_request

SERVER_KEY = "GEOIP_COUNTRY_CODE"
HEADER_KEY = "HTTP_CF_IPCOUNTRY"
PROXY = "173.245.48.10"


def _analyze(meta_key, value, remote="198.51.100.7"):
    request = make_request(ip=remote)
    if value is not None:
        request.META[meta_key] = value
    return GeoAnalyzer().analyze(request, make_history(ip=remote))


@pytest.fixture
def br_only(settings):
    settings.RISK_GUARDIAN = {"GEO_COUNTRY_META_KEY": SERVER_KEY, "GEO_ALLOWED_COUNTRIES": ["br"]}


def test_does_nothing_without_meta_key():
    assert _analyze(SERVER_KEY, "NL") == (0, None)


@pytest.mark.usefixtures("br_only")
class TestServerProvidedCountry:
    def test_allowed_country(self):
        assert _analyze(SERVER_KEY, "BR") == (0, None)

    def test_unexpected_country(self):
        assert _analyze(SERVER_KEY, "nl") == (25, "unexpected_country:NL")

    @pytest.mark.parametrize("value", [None, "", "XX", "--"])
    def test_unknown_country_is_not_penalized(self, value):
        assert _analyze(SERVER_KEY, value) == (0, None)

    def test_tor(self):
        assert _analyze(SERVER_KEY, "T1") == (40, "tor_exit")


def test_without_allowed_list_only_tor_scores(settings):
    settings.RISK_GUARDIAN = {"GEO_COUNTRY_META_KEY": SERVER_KEY}
    assert _analyze(SERVER_KEY, "NL") == (0, None)
    assert _analyze(SERVER_KEY, "T1") == (40, "tor_exit")


def test_scores_are_configurable(settings):
    settings.RISK_GUARDIAN = {
        "GEO_COUNTRY_META_KEY": SERVER_KEY,
        "GEO_ALLOWED_COUNTRIES": ["BR"],
        "GEO_UNEXPECTED_COUNTRY_SCORE": 10,
        "GEO_TOR_SCORE": 80,
    }
    assert _analyze(SERVER_KEY, "NL") == (10, "unexpected_country:NL")
    assert _analyze(SERVER_KEY, "T1") == (80, "tor_exit")


class TestHeaderProvidedCountry:
    def test_header_from_untrusted_client_is_ignored(self, settings):
        settings.RISK_GUARDIAN = {
            "GEO_COUNTRY_META_KEY": HEADER_KEY,
            "GEO_ALLOWED_COUNTRIES": ["BR"],
            "TRUSTED_PROXIES": ["173.245.48.0/20"],
        }
        # A client that is not the CDN may claim any country, or Tor to frame someone.
        assert _analyze(HEADER_KEY, "T1", remote="198.51.100.7") == (0, None)

    def test_header_from_trusted_proxy_is_read(self, settings):
        settings.RISK_GUARDIAN = {
            "GEO_COUNTRY_META_KEY": HEADER_KEY,
            "GEO_ALLOWED_COUNTRIES": ["BR"],
            "TRUSTED_PROXIES": ["173.245.48.0/20"],
        }
        assert _analyze(HEADER_KEY, "NL", remote=PROXY) == (25, "unexpected_country:NL")
