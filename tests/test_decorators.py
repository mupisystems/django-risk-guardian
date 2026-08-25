from __future__ import annotations

from django.http import HttpResponse
from django.test import RequestFactory

from risk_guardian.assessment import RiskAssessment
from risk_guardian.decorators import require_no_challenge, require_risk_below


def _view(request):
    return HttpResponse("OK", status=200)


def _make_request(score: int | None = None, challenged: bool = False):
    request = RequestFactory().get("/api/test/")
    if score is not None:
        request.risk = RiskAssessment(score=score, challenged=challenged)
    return request


class TestRequireRiskBelow:
    def test_allows_score_below_threshold(self):
        response = require_risk_below(50)(_view)(_make_request(score=49))
        assert response.status_code == 200
        assert response.content == b"OK"

    def test_blocks_score_at_threshold(self):
        response = require_risk_below(50)(_view)(_make_request(score=50))
        assert response.status_code == 429

    def test_blocks_score_above_threshold(self):
        response = require_risk_below(50)(_view)(_make_request(score=80))
        assert response.status_code == 429

    def test_passes_through_when_no_risk_attached(self):
        # Middleware disabled or path ignored: request has no .risk at all
        response = require_risk_below(50)(_view)(_make_request())
        assert response.status_code == 200

    def test_zero_score_passes(self):
        # RiskAssessment(score=0) is a truthy object, so the guard still runs
        response = require_risk_below(50)(_view)(_make_request(score=0))
        assert response.status_code == 200

    def test_custom_response_code(self):
        response = require_risk_below(50, response_code=403)(_view)(_make_request(score=90))
        assert response.status_code == 403

    def test_preserves_view_metadata(self):
        decorated = require_risk_below(50)(_view)
        assert decorated.__name__ == "_view"

    def test_forwards_args_and_kwargs(self):
        def view(request, pk, action="view"):
            return HttpResponse(f"{pk}:{action}", status=200)

        response = require_risk_below(50)(view)(_make_request(score=10), 42, action="edit")
        assert response.content == b"42:edit"


class TestRequireNoChallenge:
    def test_allows_when_not_challenged(self):
        response = require_no_challenge(_view)(_make_request(score=10, challenged=False))
        assert response.status_code == 200

    def test_blocks_when_challenged(self):
        response = require_no_challenge(_view)(_make_request(score=60, challenged=True))
        assert response.status_code == 429

    def test_passes_through_when_no_risk_attached(self):
        response = require_no_challenge(_view)(_make_request())
        assert response.status_code == 200

    def test_bare_decorator_form(self):
        # @require_no_challenge
        decorated = require_no_challenge(_view)
        assert decorated(_make_request(score=60, challenged=True)).status_code == 429

    def test_called_decorator_form(self):
        # @require_no_challenge(response_code=403)
        decorated = require_no_challenge(response_code=403)(_view)
        assert decorated(_make_request(score=60, challenged=True)).status_code == 403
        assert decorated(_make_request(score=10)).status_code == 200

    def test_preserves_view_metadata(self):
        assert require_no_challenge(_view).__name__ == "_view"

    def test_forwards_args_and_kwargs(self):
        def view(request, pk, action="view"):
            return HttpResponse(f"{pk}:{action}", status=200)

        response = require_no_challenge(view)(_make_request(score=10), 42, action="edit")
        assert response.content == b"42:edit"
