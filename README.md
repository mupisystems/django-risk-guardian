# django-risk-guardian

Middleware Django reutilizável para detecção de bots e usuários maliciosos via score de risco composto.

Reusable Django middleware for bot detection and malicious user scoring through composite risk assessment.

---

**[Português](#português) | [English](#english)**

---

## Português

### O que é

Um middleware que analisa cada requisição HTTP e atribui um **score de risco (0–100)** baseado em múltiplos sinais: taxa de requisições, user-agent, sessão, padrões de navegação e timing. Sinais fracos isolados não bloqueiam, mas combinados identificam bots sem falsos positivos.

### Instalação

```toml
# pyproject.toml
[tool.poetry.dependencies]
django-risk-guardian = { git = "https://github.com/suaempresa/django-risk-guardian" }
```

```python
# settings.py (3 linhas)
INSTALLED_APPS += ["risk_guardian"]

MIDDLEWARE = [
    "risk_guardian.middleware.RiskGuardianMiddleware",
    # ... demais middlewares
]
```

### Requisitos

- Python 3.11+
- Django 4.2+
- Redis (via django-redis)

### Configuração

Todos os parâmetros têm defaults funcionais. Sobrescreva apenas o necessário:

```python
RISK_GUARDIAN = {
    # Comportamento geral
    "ENABLED": True,
    "CACHE_BACKEND": "default",           # backend do Django cache (deve ser Redis)
    "CACHE_PREFIX": "rg",
    "LOG_ALL_SCORES": False,

    # Thresholds (0–100)
    "SCORE_THRESHOLD_BLOCK": 80,          # bloqueia a requisição
    "SCORE_THRESHOLD_CHALLENGE": 50,      # sinaliza para a view (ex: exigir 2FA)

    # Bloqueio
    "BLOCK_RESPONSE_CODE": 429,
    "BLOCK_TTL_SECONDS": 3600,

    # Histórico deslizante
    "HISTORY_WINDOW_SECONDS": 300,        # janela de 5 min
    "HISTORY_MAX_REQUESTS": 100,

    # Paths ignorados
    "IGNORE_PATHS": ["/health/", "/metrics/", "/__debug__/", "/favicon.ico"],

    # Analyzers ativos (ordem importa)
    "ANALYZERS": [
        "risk_guardian.analyzers.RateAnalyzer",
        "risk_guardian.analyzers.UserAgentAnalyzer",
        "risk_guardian.analyzers.SessionAnalyzer",
        "risk_guardian.analyzers.PatternAnalyzer",
        "risk_guardian.analyzers.TimingAnalyzer",
    ],
}
```

### Uso nas views

Após o middleware processar, toda view tem acesso a `request.risk`:

```python
def minha_view(request):
    if request.risk.challenged:
        return redirect("verificacao_2fa")

    print(request.risk.score)      # int (0–100)
    print(request.risk.reasons)    # ["high_rate", "outdated_browser"]
    print(request.risk.blocked)    # bool
```

### Decorators

```python
from risk_guardian.decorators import require_risk_below, require_no_challenge

@require_risk_below(50)
def endpoint_sensivel(request):
    ...

@require_no_challenge
def area_restrita(request):
    ...
```

### Signals

```python
from django.dispatch import receiver
from risk_guardian.signals import ip_blocked

@receiver(ip_blocked)
def notificar_bloqueio(sender, ip, score, reasons, **kwargs):
    SlackNotifier.send(f"IP bloqueado: {ip} (score={score})")
```

Signals disponíveis: `ip_blocked`, `risk_assessed`, `challenge_required`.

### Analyzers

| Analyzer | Detecta | Score máximo |
|---|---|---|
| **RateAnalyzer** | Volume anormal de requisições por IP | +50 |
| **UserAgentAnalyzer** | UAs de bots, browsers desatualizados, UA vazio | +40 |
| **SessionAnalyzer** | Sessão ausente, rotação de UA, sessões excessivas por IP | +35 |
| **PatternAnalyzer** | Paths de scan (.env, wp-admin), taxa de erro alta, diversidade de paths | +60 |
| **TimingAnalyzer** | Intervalos artificialmente regulares entre requisições | +30 |

### Testes

```bash
pip install pytest pytest-django fakeredis
pytest tests/ -v
```

---

## English

### What is it

A middleware that analyzes each HTTP request and assigns a **risk score (0–100)** based on multiple signals: request rate, user-agent, session, navigation patterns, and timing. Weak signals alone don't block, but combined they identify bots without false positives.

### Installation

```toml
# pyproject.toml
[tool.poetry.dependencies]
django-risk-guardian = { git = "https://github.com/yourcompany/django-risk-guardian" }
```

```python
# settings.py (3 lines)
INSTALLED_APPS += ["risk_guardian"]

MIDDLEWARE = [
    "risk_guardian.middleware.RiskGuardianMiddleware",
    # ... other middlewares
]
```

### Requirements

- Python 3.11+
- Django 4.2+
- Redis (via django-redis)

### Configuration

All parameters have functional defaults. Override only what you need:

```python
RISK_GUARDIAN = {
    # General behavior
    "ENABLED": True,
    "CACHE_BACKEND": "default",           # Django cache backend (should be Redis)
    "CACHE_PREFIX": "rg",
    "LOG_ALL_SCORES": False,

    # Thresholds (0–100)
    "SCORE_THRESHOLD_BLOCK": 80,          # blocks the request
    "SCORE_THRESHOLD_CHALLENGE": 50,      # flags for the view (e.g., require 2FA)

    # Blocking
    "BLOCK_RESPONSE_CODE": 429,
    "BLOCK_TTL_SECONDS": 3600,

    # Sliding history
    "HISTORY_WINDOW_SECONDS": 300,        # 5-minute window
    "HISTORY_MAX_REQUESTS": 100,

    # Ignored paths
    "IGNORE_PATHS": ["/health/", "/metrics/", "/__debug__/", "/favicon.ico"],

    # Active analyzers (order matters)
    "ANALYZERS": [
        "risk_guardian.analyzers.RateAnalyzer",
        "risk_guardian.analyzers.UserAgentAnalyzer",
        "risk_guardian.analyzers.SessionAnalyzer",
        "risk_guardian.analyzers.PatternAnalyzer",
        "risk_guardian.analyzers.TimingAnalyzer",
    ],
}
```

### Usage in views

After the middleware processes a request, every view has access to `request.risk`:

```python
def my_view(request):
    if request.risk.challenged:
        return redirect("2fa_verification")

    print(request.risk.score)      # int (0–100)
    print(request.risk.reasons)    # ["high_rate", "outdated_browser"]
    print(request.risk.blocked)    # bool
```

### Decorators

```python
from risk_guardian.decorators import require_risk_below, require_no_challenge

@require_risk_below(50)
def sensitive_endpoint(request):
    ...

@require_no_challenge
def restricted_area(request):
    ...
```

### Signals

```python
from django.dispatch import receiver
from risk_guardian.signals import ip_blocked

@receiver(ip_blocked)
def notify_block(sender, ip, score, reasons, **kwargs):
    SlackNotifier.send(f"IP blocked: {ip} (score={score})")
```

Available signals: `ip_blocked`, `risk_assessed`, `challenge_required`.

### Analyzers

| Analyzer | Detects | Max score |
|---|---|---|
| **RateAnalyzer** | Abnormal request volume per IP | +50 |
| **UserAgentAnalyzer** | Bot UAs, outdated browsers, missing UA | +40 |
| **SessionAnalyzer** | Missing session, UA rotation, excessive sessions per IP | +35 |
| **PatternAnalyzer** | Scan paths (.env, wp-admin), high error rate, path diversity | +60 |
| **TimingAnalyzer** | Artificially regular intervals between requests | +30 |

### Tests

```bash
pip install pytest pytest-django fakeredis
pytest tests/ -v
```

---

## License

MIT
