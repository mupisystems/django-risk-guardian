from __future__ import annotations

from django.core.cache import caches
from django.http import HttpResponse
from django.test import RequestFactory

from risk_guardian.conf import get_config
from risk_guardian.middleware import RiskGuardianMiddleware
from risk_guardian.network import get_client_ip, ip_in

PROXY = "10.0.0.5"


def _request(remote="198.51.100.7", **meta):
    request = RequestFactory().get("/", **meta)
    request.META["REMOTE_ADDR"] = remote
    return request


def _config(**overrides):
    return {**get_config(), **overrides}


class TestGetClientIp:
    def test_default_uses_remote_addr_and_ignores_forgeable_headers(self):
        request = _request(HTTP_X_REAL_IP="203.0.113.1", HTTP_X_FORWARDED_FOR="203.0.113.2")
        assert get_client_ip(request, _config()) == "198.51.100.7"

    def test_header_ignored_when_request_does_not_come_from_trusted_proxy(self):
        config = _config(CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR", TRUSTED_PROXIES=[PROXY])
        request = _request(remote="198.51.100.7", HTTP_X_FORWARDED_FOR="203.0.113.2")
        assert get_client_ip(request, config) == "198.51.100.7"

    def test_header_honored_from_trusted_proxy(self):
        config = _config(CLIENT_IP_HEADER="HTTP_X_REAL_IP", TRUSTED_PROXIES=["10.0.0.0/8"])
        request = _request(remote=PROXY, HTTP_X_REAL_IP="203.0.113.1")
        assert get_client_ip(request, config) == "203.0.113.1"

    def test_forwarded_for_uses_rightmost_untrusted_hop(self):
        # The client wrote "1.1.1.1"; the trusted proxy appended the real peer.
        config = _config(CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR", TRUSTED_PROXIES=["10.0.0.0/8"])
        request = _request(remote=PROXY, HTTP_X_FORWARDED_FOR="1.1.1.1, 203.0.113.9, 10.0.0.3")
        assert get_client_ip(request, config) == "203.0.113.9"

    def test_malformed_header_falls_back_to_remote_addr(self):
        config = _config(CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR", TRUSTED_PROXIES=[PROXY])
        request = _request(remote=PROXY, HTTP_X_FORWARDED_FOR="not-an-ip")
        assert get_client_ip(request, config) == PROXY

    def test_only_trusted_hops_falls_back_to_remote_addr(self):
        config = _config(CLIENT_IP_HEADER="HTTP_X_FORWARDED_FOR", TRUSTED_PROXIES=["10.0.0.0/8"])
        request = _request(remote=PROXY, HTTP_X_FORWARDED_FOR="10.0.0.3")
        assert get_client_ip(request, config) == PROXY

    def test_missing_header_falls_back_to_remote_addr(self):
        config = _config(CLIENT_IP_HEADER="HTTP_X_REAL_IP", TRUSTED_PROXIES=[PROXY])
        assert get_client_ip(_request(remote=PROXY), config) == PROXY


class TestIpIn:
    def test_matches_single_ip_and_cidr(self):
        assert ip_in("203.0.113.9", ["203.0.113.9"])
        assert ip_in("203.0.113.9", ["203.0.113.0/24"])
        assert ip_in("2001:db8::1", ["2001:db8::/32"])

    def test_no_match(self):
        assert not ip_in("198.51.100.1", ["203.0.113.0/24"])

    def test_empty_list_and_invalid_ip(self):
        assert not ip_in("203.0.113.9", [])
        assert not ip_in("not-an-ip", ["0.0.0.0/0"])


def _ok_view(request):
    return HttpResponse("OK")


class TestMiddlewareIp:
    def test_forged_x_real_ip_does_not_bypass_a_block(self):
        config = get_config()
        caches[config["CACHE_BACKEND"]].set(f"{config['CACHE_PREFIX']}:blocked:198.51.100.7", 1, 60)
        request = _request(remote="198.51.100.7", HTTP_X_REAL_IP="203.0.113.50")
        response = RiskGuardianMiddleware(_ok_view)(request)
        assert response.status_code == 429

    def test_forged_x_real_ip_cannot_get_another_ip_blocked(self, settings):
        settings.RISK_GUARDIAN = {"SCORE_THRESHOLD_BLOCK": 1}
        request = _request(remote="198.51.100.7", HTTP_X_REAL_IP="203.0.113.50", HTTP_USER_AGENT="curl/8.5.0")
        RiskGuardianMiddleware(_ok_view)(request)
        config = get_config()
        cache = caches[config["CACHE_BACKEND"]]
        assert cache.get(f"{config['CACHE_PREFIX']}:blocked:198.51.100.7")
        assert not cache.get(f"{config['CACHE_PREFIX']}:blocked:203.0.113.50")

    def test_allowlisted_ip_is_neither_scored_nor_blocked(self, settings):
        settings.RISK_GUARDIAN = {"ALLOWLIST_IPS": ["198.51.100.0/24"]}
        config = get_config()
        caches[config["CACHE_BACKEND"]].set(f"{config['CACHE_PREFIX']}:blocked:198.51.100.7", 1, 60)
        request = _request(remote="198.51.100.7", HTTP_USER_AGENT="curl/8.5.0")
        response = RiskGuardianMiddleware(_ok_view)(request)
        assert response.status_code == 200
        assert not hasattr(request, "risk")
