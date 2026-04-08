from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest
from django.core.cache import caches
from django.http import HttpResponse
from django.test import RequestFactory

from risk_guardian.conf import get_config
from risk_guardian.middleware import RiskGuardianMiddleware


def dummy_view(request):
    return HttpResponse("OK", status=200)


class TestRiskGuardianMiddleware:
    def _get_middleware(self, view=None):
        return RiskGuardianMiddleware(view or dummy_view)

    def _make_request(self, path="/api/test/", ip="1.2.3.4", ua="Mozilla/5.0 Chrome/125.0.0.0"):
        factory = RequestFactory()
        request = factory.get(path)
        request.META["REMOTE_ADDR"] = ip
        request.META["HTTP_USER_AGENT"] = ua
        request.session = MagicMock()
        request.session.session_key = "test-session"
        return request

    def test_ignored_path_passes_through(self):
        middleware = self._get_middleware()
        request = self._make_request(path="/health/")
        response = middleware(request)
        assert response.status_code == 200
        assert not hasattr(request, "risk")

    def test_blocked_ip_returns_429(self):
        config = get_config()
        cache = caches[config["CACHE_BACKEND"]]
        prefix = config["CACHE_PREFIX"]
        cache.set(f"{prefix}:blocked:1.2.3.4", 1, 3600)

        middleware = self._get_middleware()
        request = self._make_request()
        response = middleware(request)
        assert response.status_code == 429

    def test_analyzer_exception_does_not_break_request(self):
        def failing_view(request):
            return HttpResponse("OK", status=200)

        middleware = self._get_middleware(failing_view)

        # Patch one analyzer to raise
        original_analyze = middleware._analyzers[0].analyze
        middleware._analyzers[0].analyze = MagicMock(side_effect=RuntimeError("boom"))

        request = self._make_request()
        response = middleware(request)
        assert response.status_code == 200
        assert hasattr(request, "risk")

    def test_low_score_passes_with_risk_attached(self):
        middleware = self._get_middleware()
        request = self._make_request()
        response = middleware(request)
        assert response.status_code == 200
        assert hasattr(request, "risk")
        assert request.risk.score >= 0
        assert request.risk.blocked is False

    def test_high_score_blocks(self):
        middleware = self._get_middleware()
        request = self._make_request()

        # Make all analyzers return high scores
        for analyzer in middleware._analyzers:
            analyzer.analyze = MagicMock(return_value=(20, "test_reason"))

        response = middleware(request)
        # 5 analyzers * 20 = 100 >= 80 threshold
        assert response.status_code == 429

    def test_disabled_middleware_passes_through(self):
        with patch("risk_guardian.middleware.get_config") as mock_config:
            config = get_config()
            config["ENABLED"] = False
            mock_config.return_value = config
            middleware = RiskGuardianMiddleware(dummy_view)
            request = self._make_request()
            response = middleware(request)
            assert response.status_code == 200
            assert not hasattr(request, "risk")

    def test_challenge_threshold(self):
        middleware = self._get_middleware()
        request = self._make_request()

        # Score between challenge (50) and block (80)
        for analyzer in middleware._analyzers:
            analyzer.analyze = MagicMock(return_value=(12, "test"))

        response = middleware(request)
        # 5 * 12 = 60, above 50 challenge but below 80 block
        assert response.status_code == 200
        assert request.risk.challenged is True
        assert request.risk.blocked is False
