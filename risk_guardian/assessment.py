from __future__ import annotations

from dataclasses import dataclass, field

from risk_guardian.history import AccessHistory


@dataclass
class RiskAssessment:
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    blocked: bool = False
    challenged: bool = False
    history: AccessHistory | None = None

    def add(self, delta: int, reason: str | None) -> None:
        if delta <= 0:
            return
        self.score = min(self.score + delta, 100)
        if reason:
            self.reasons.append(reason)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "reasons": self.reasons,
            "blocked": self.blocked,
            "challenged": self.challenged,
        }
