from __future__ import annotations

from abc import ABC, abstractmethod

from risk_guardian.history import AccessHistory


class BaseAnalyzer(ABC):
    """
    Cada analyzer é stateless — não guarda estado entre requisições.
    Recebe o request e o histórico, retorna (delta_score, reason).
    - delta_score: int, 0 se sem sinal, positivo se suspeito
    - reason: str identificando o sinal, None se delta = 0
    """

    @abstractmethod
    def analyze(self, request, history: AccessHistory) -> tuple[int, str | None]: ...
