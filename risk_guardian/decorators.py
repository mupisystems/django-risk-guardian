from __future__ import annotations

from functools import wraps

from django.http import HttpResponse


def require_risk_below(threshold: int, response_code: int = 429):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            risk = getattr(request, "risk", None)
            if risk and risk.score >= threshold:
                return HttpResponse("Too Many Requests", status=response_code)
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def require_no_challenge(view_func=None, response_code: int = 429):
    def decorator(func):
        @wraps(func)
        def _wrapped(request, *args, **kwargs):
            risk = getattr(request, "risk", None)
            if risk and risk.challenged:
                return HttpResponse("Too Many Requests", status=response_code)
            return func(request, *args, **kwargs)
        return _wrapped

    if view_func is not None:
        return decorator(view_func)
    return decorator
