from __future__ import annotations

import json
import logging
import time
from importlib import import_module

from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse

from risk_guardian.assessment import RiskAssessment
from risk_guardian.conf import get_config
from risk_guardian.history import AccessHistory
from risk_guardian.network import get_client_ip, ip_in
from risk_guardian.signals import challenge_required, ip_blocked, risk_assessed

logger = logging.getLogger("risk_guardian")

MODES = ("enforce", "observe")
MONITOR_THRESHOLD = 20


def _load_analyzer(dotted_path):
    module_path, class_name = dotted_path.rsplit(".", 1)
    module = import_module(module_path)
    return getattr(module, class_name)()


class RiskGuardianMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self._config = get_config()
        if self._config["MODE"] not in MODES:
            raise ImproperlyConfigured(f"RISK_GUARDIAN['MODE'] must be one of {MODES}, not {self._config['MODE']!r}")
        self._observe = self._config["MODE"] == "observe"
        self._analyzers = [_load_analyzer(path) for path in self._config["ANALYZERS"]]

    def __call__(self, request):
        config = self._config

        if not config["ENABLED"]:
            return self.get_response(request)

        path = request.path
        if any(path.startswith(ignored) for ignored in config["IGNORE_PATHS"]):
            return self.get_response(request)

        ip = get_client_ip(request, config)
        if ip_in(ip, config["ALLOWLIST_IPS"]):
            return self.get_response(request)

        cache = caches[config["CACHE_BACKEND"]]
        prefix = config["CACHE_PREFIX"]

        blocked_key = f"{prefix}:blocked:{ip}"
        if not self._observe and cache.get(blocked_key):
            return HttpResponse("Too Many Requests", status=config["BLOCK_RESPONSE_CODE"])

        session_key = None
        session = getattr(request, "session", None)
        if session:
            session_key = getattr(session, "session_key", None)

        history = AccessHistory(ip, session_key)
        assessment = RiskAssessment(history=history)

        for analyzer in self._analyzers:
            try:
                delta, reason = analyzer.analyze(request, history)
                assessment.add(delta, reason)
            except Exception:
                logger.exception(
                    json.dumps(
                        {
                            "event": "analyzer_error",
                            "ip": ip,
                            "analyzer": type(analyzer).__name__,
                        }
                    )
                )

        assessment.decision = self._decide(assessment.score)

        if assessment.decision == "block":
            self._log_event("ip_blocked", ip, request, assessment)
            if not self._observe:
                assessment.blocked = True
                cache.set(blocked_key, 1, config["BLOCK_TTL_SECONDS"])
                ip_blocked.send(sender=self.__class__, ip=ip, score=assessment.score, reasons=assessment.reasons)
                return HttpResponse("Too Many Requests", status=config["BLOCK_RESPONSE_CODE"])

        if assessment.decision == "challenge" and not self._observe:
            assessment.challenged = True
            challenge_required.send(sender=self.__class__, ip=ip, request=request, score=assessment.score)

        request.risk = assessment

        start = time.time()
        response = self.get_response(request)
        duration_ms = (time.time() - start) * 1000

        history.record(
            {
                "path": path,
                "method": request.method,
                "status": response.status_code,
                "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                "duration_ms": duration_ms,
            }
        )

        if assessment.score > 0:
            risk_assessed.send(sender=self.__class__, ip=ip, request=request, assessment=assessment)

        if assessment.score >= MONITOR_THRESHOLD or config["LOG_ALL_SCORES"]:
            self._log_event("risk_assessed", ip, request, assessment)

        if assessment.decision == "challenge":
            self._log_event("challenge_required", ip, request, assessment)

        return response

    def _decide(self, score: int) -> str:
        if score >= self._config["SCORE_THRESHOLD_BLOCK"]:
            return "block"
        if score >= self._config["SCORE_THRESHOLD_CHALLENGE"]:
            return "challenge"
        if score >= MONITOR_THRESHOLD:
            return "monitor"
        return "allow"

    def _log_event(self, event: str, ip: str, request, assessment: RiskAssessment):
        request_id = getattr(request, "request_id", None) or request.META.get(self._config["REQUEST_ID_META_KEY"], "")
        log_data = json.dumps(
            {
                "event": event,
                "mode": self._config["MODE"],
                "decision": assessment.decision,
                "ip": ip,
                "method": request.method,
                "path": request.path,
                "request_id": request_id,
                "score": assessment.score,
                "reasons": assessment.reasons,
            }
        )
        if event == "ip_blocked":
            logger.warning(log_data)
        elif event == "analyzer_error":
            logger.error(log_data)
        else:
            logger.info(log_data)
