# django-risk-guardian

[![PyPI](https://img.shields.io/pypi/v/django-risk-guardian.svg)](https://pypi.org/project/django-risk-guardian/)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Django 4.2+](https://img.shields.io/badge/django-4.2%2B-green.svg)
[![CI](https://github.com/mupisystems/django-risk-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/mupisystems/django-risk-guardian/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**Middleware de score de risco comportamental para Django.**

**Behavior-based risk scoring middleware for Django.**

> Rate limiting detecta volume. Risk Guardian detecta comportamento.
>
> Rate limiting detects volume. Risk Guardian detects behavior.

---

**[Português](#português) | [English](#english)**

---

## Português

### O que é

Um middleware que analisa cada requisição HTTP e atribui um **score de risco (0–100)** a partir de múltiplos sinais comportamentais: taxa de requisições, user-agent, sessão, padrões de navegação e timing. Sinais fracos isolados não bloqueiam nada — combinados, revelam comportamento automatizado ou abusivo.

Detecção de bots é a aplicação mais óbvia do mecanismo, não o limite dele. O que o middleware entrega é um score que sua aplicação usa para decidir.

### Como funciona

```
Request → Analyzers → Risk Score → Policy → Allow / Monitor / Challenge / Block
```

Cada analyzer contribui com um delta e uma razão. O score composto é comparado com os thresholds configurados e a decisão é aplicada antes da view.

### Faixas de decisão

| Score | Decisão | O que acontece |
|---|---|---|
| **0–19** | Allow | Requisição segue normalmente, sem log |
| **20–49** | Monitor | Segue normalmente, mas emite evento `risk_assessed` para observabilidade |
| **50–79** | Challenge | `request.risk.challenged = True` — a view decide (2FA, CAPTCHA, confirmação) |
| **80+** | Block | HTTP 429 e IP bloqueado por `BLOCK_TTL_SECONDS` |

Os limiares de Challenge e Block são configuráveis via `SCORE_THRESHOLD_CHALLENGE` e `SCORE_THRESHOLD_BLOCK`.

### Modo observação

Com `"MODE": "observe"` o middleware calcula o score e registra a decisão que tomaria, mas não age: nunca responde 429, não grava bloqueio no cache (e ignora bloqueios antigos), não marca `request.risk.challenged` e não dispara os signals `ip_blocked` e `challenge_required`. A decisão fica em `request.risk.decision` (`allow`, `monitor`, `challenge` ou `block`) e no campo `decision` dos logs.

Use ao instalar o pacote num projeto em produção: depois de uma ou duas semanas de tráfego real, os eventos com `decision` `challenge` e `block` mostram o que seria barrado, e os limiares (ou a `ALLOWLIST_IPS`) são ajustados antes de passar a `"enforce"`.

### Why Risk Guardian?

Cada camada de defesa enxerga uma dimensão diferente do tráfego:

| Técnica | Detecta |
|---|---|
| Rate limiting | Volume |
| CAPTCHA | Automação |
| IP blocking | Origem |
| WAF | Padrões conhecidos |
| **Risk Guardian** | **Comportamento composto** |

**Risk Guardian complementa essas camadas — não substitui nenhuma delas.** Continue usando WAF, rate limiting e CAPTCHA. O que falta nesse conjunto é a leitura de comportamento: um IP com taxa média + UA desatualizado + sem sessão em path autenticado passa por todos os filtros acima individualmente, mas é muito mais suspeito do que qualquer um desses sinais isolado. O score composto captura exatamente isso.

### Casos de uso

- Bots e scrapers que respeitam limites de taxa
- Brute force distribuído
- Credential stuffing
- Scanners de vulnerabilidade (`.env`, `wp-admin`, paths de probe)
- Comportamento anômalo de navegação (timing robótico, rotação de UA)
- Abuso de endpoints caros ou sensíveis

### Instalação

```bash
pip install django-risk-guardian
```

```python
# settings.py
INSTALLED_APPS += ["risk_guardian"]

MIDDLEWARE = [
    # ...
    "django.contrib.sessions.middleware.SessionMiddleware",
    "risk_guardian.middleware.RiskGuardianMiddleware",  # depois do SessionMiddleware
    # ... demais middlewares
]
```

O middleware precisa vir **depois** do `SessionMiddleware`: antes dele, `request.session` não existe e o `SessionAnalyzer` não enxerga nenhuma sessão.

### IP do cliente

Por padrão o IP é o `REMOTE_ADDR`, o único valor que o cliente não escolhe. Atrás de um proxy reverso, prefira corrigir o `REMOTE_ADDR` no próprio proxy (por exemplo, `real_ip` no nginx). Se precisar ler um cabeçalho, informe qual e quem pode enviá-lo:

```python
RISK_GUARDIAN = {
    "CLIENT_IP_HEADER": "HTTP_X_FORWARDED_FOR",   # chave do request.META
    "TRUSTED_PROXIES": ["10.0.0.0/8"],            # quem pode definir o cabeçalho
}
```

O cabeçalho só é lido quando a requisição vem de um `TRUSTED_PROXIES`, e o cliente é o endereço mais à direita que não é proxy confiável. Confiar num cabeçalho sem essa checagem deixa o atacante escolher o próprio IP: ele escapa do bloqueio e pode fazer o middleware bloquear o IP de outra pessoa.

IPs e redes em `ALLOWLIST_IPS` (aceita CIDR) nunca são pontuados nem bloqueados — útil para escritórios e balcões onde muita gente entra pelo mesmo IP.

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
    "MODE": "enforce",                    # ou "observe" (ver "Modo observação")
    "CACHE_BACKEND": "default",           # backend do Django cache (deve ser Redis)
    "CACHE_PREFIX": "rg",
    "LOG_ALL_SCORES": False,
    "REQUEST_ID_META_KEY": "HTTP_X_REQUEST_ID",  # id da requisição nos logs

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

    # IP do cliente (ver "IP do cliente")
    "CLIENT_IP_HEADER": None,
    "TRUSTED_PROXIES": [],
    "ALLOWLIST_IPS": [],

    # Paths de varredura somados à lista do PatternAnalyzer
    "EXTRA_SCAN_PATHS": [],

    # Logins e cadastros por IP (AuthAnalyzer)
    "AUTH_WINDOW_SECONDS": 3600,
    "AUTH_ACCOUNTS_MONITOR": 3,
    "AUTH_ACCOUNTS_CHALLENGE": 5,
    "AUTH_FAILED_ACCOUNTS_CHALLENGE": 3,
    "AUTH_FAILED_ACCOUNTS_BLOCK": 5,
    "AUTH_SIGNUPS_CHALLENGE": 3,

    # País da requisição (GeoAnalyzer)
    "GEO_COUNTRY_META_KEY": None,
    "GEO_ALLOWED_COUNTRIES": [],
    "GEO_UNEXPECTED_COUNTRY_SCORE": 25,
    "GEO_TOR_SCORE": 40,

    # Analyzers ativos (ordem importa)
    "ANALYZERS": [
        "risk_guardian.analyzers.RateAnalyzer",
        "risk_guardian.analyzers.UserAgentAnalyzer",
        "risk_guardian.analyzers.SessionAnalyzer",
        "risk_guardian.analyzers.PatternAnalyzer",
        "risk_guardian.analyzers.TimingAnalyzer",
        "risk_guardian.analyzers.AuthAnalyzer",
        "risk_guardian.analyzers.GeoAnalyzer",
    ],
}
```

### Chaves no cache

Todas as chaves usam o `CACHE_PREFIX` configurado (default `rg`):

| Chave | TTL | Conteúdo |
|---|---|---|
| `{prefix}:hist:ip:{ip}` | `HISTORY_WINDOW_SECONDS` + 60 | Histórico deslizante do IP |
| `{prefix}:hist:sess:{session_key}` | `HISTORY_WINDOW_SECONDS` + 60 | Histórico deslizante da sessão |
| `{prefix}:blocked:{ip}` | `BLOCK_TTL_SECONDS` | Flag de IP bloqueado (checada antes de qualquer análise) |
| `{prefix}:sess_set:{ip}` | 300 | Conjunto de sessões distintas vistas no IP |
| `{prefix}:auth:{ok\|fail\|signup}:{ip}` | `AUTH_WINDOW_SECONDS` + 60 | Contas que logaram, falharam ou se cadastraram no IP (hash, nunca o e-mail) |

Cada entrada de histórico guarda `ts`, `path`, `method`, `status`, `ua` (truncado em 100 chars) e `duration_ms`. A lista é limitada a `HISTORY_MAX_REQUESTS` entradas.

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

Signals disponíveis: `ip_blocked`, `risk_assessed`, `challenge_required`, `email_risk_assessed`.

### Analyzers

| Analyzer | Detecta | Score máximo | Reasons emitidos |
|---|---|---|---|
| **RateAnalyzer** | Volume anormal de requisições por IP (a partir de 5 amostras) | +50 | `critical_rate`, `high_rate`, `medium_rate` |
| **UserAgentAnalyzer** | UAs de bots, UA mínimo (`Mozilla/5.0` sem plataforma), browsers desatualizados, UA vazio | +40 | `bot_ua:curl`, `minimal_ua`, `missing_ua`, `outdated_browser` |
| **SessionAnalyzer** | Sessão ausente, rotação de UA, sessões excessivas por IP | +35 | `no_session_on_auth_path`, `session_ua_rotation`, `excessive_sessions_per_ip` |
| **PatternAnalyzer** | Paths de scan (.env, wp-admin, painéis admin), taxa de erro alta, diversidade de paths | +60 | `scan_attempt:/.env`, `high_error_rate`, `excessive_path_diversity` |
| **TimingAnalyzer** | Intervalos artificialmente regulares entre requisições | +30 | `robotic_timing` |
| **AuthAnalyzer** | Muitas contas logando ou falhando no mesmo IP, cadastros em série | +80 | `credential_stuffing`, `failed_logins_many_accounts`, `logins_many_accounts`, `logins_several_accounts`, `signup_velocity` |
| **GeoAnalyzer** | País fora da lista permitida, rede Tor (país resolvido pelo servidor web ou pela CDN) | +40 | `unexpected_country:NL`, `tor_exit` |

### AuthAnalyzer (credential stuffing e cadastro automatizado)

Quem testa uma lista de e-mails e senhas roubados tenta uma ou duas vezes por conta, então o bloqueio por conta nunca dispara. O sinal é a quantidade de **contas distintas** que um mesmo IP toca numa janela (`AUTH_WINDOW_SECONDS`, padrão 1 h).

Os receivers do pacote registram cada login (`user_logged_in`), falha (`user_login_failed`) e, com django-allauth instalado, cadastro (`user_signed_up`). As contas são guardadas como hash com a `SECRET_KEY` — o cache não guarda e-mail nem usuário.

| Situação no IP, dentro da janela | Delta | Reason |
|---|---|---|
| 5+ contas com falha (`AUTH_FAILED_ACCOUNTS_BLOCK`) | +80 | `credential_stuffing` |
| 3+ contas com falha (`AUTH_FAILED_ACCOUNTS_CHALLENGE`) | +50 | `failed_logins_many_accounts` |
| 5+ contas distintas (`AUTH_ACCOUNTS_CHALLENGE`) | +50 | `logins_many_accounts` |
| 3+ contas distintas (`AUTH_ACCOUNTS_MONITOR`) | +20 | `logins_several_accounts` |
| 3+ cadastros (`AUTH_SIGNUPS_CHALLENGE`) | +50 | `signup_velocity` |

Falhas pesam mais que acertos: num escritório, dez pessoas entrando pelo mesmo IP raramente erram a senha de cinco contas diferentes; uma lista de senhas roubadas erra em cerca de metade. Por isso, sozinho, o escritório chega no máximo a **Challenge** e nunca a **Block**.

O login acontece dentro da view, depois da decisão do middleware. Os receivers somam o sinal ao `request.risk` da própria requisição (a view pode reagir na hora) e o `AuthAnalyzer` aplica o acumulado em todas as requisições seguintes do IP — é ali que o desafio ou o bloqueio acontece.

Fluxos próprios de login ou cadastro podem registrar eventos diretamente:

```python
from risk_guardian.auth_tracking import SIGNUP, record_auth_event

record_auth_event(request, SIGNUP, user.email)
```

O teste `tests/test_attack_replay.py` reproduz um credential stuffing típico — lista de senhas roubadas, uma ou duas tentativas por conta, cerca de metade das senhas já trocadas e user agent `Mozilla/5.0` puro: o IP toma uma conta e é bloqueado no 15º segundo.

### GeoAnalyzer (país da requisição)

O `GeoAnalyzer` não consulta base nenhuma: lê o código do país que o servidor web ou a CDN já resolveu, na chave `GEO_COUNTRY_META_KEY` do `request.META`. Sem essa chave configurada, não faz nada.

| Situação | Delta | Reason |
|---|---|---|
| País `T1` (rede Tor, código do Cloudflare) | +40 (`GEO_TOR_SCORE`) | `tor_exit` |
| País fora de `GEO_ALLOWED_COUNTRIES` | +25 (`GEO_UNEXPECTED_COUNTRY_SCORE`) | `unexpected_country:XX` |
| País desconhecido (`XX`, vazio) ou lista vazia | 0 | — |

Sozinho, um país inesperado fica em **Monitor**; somado a outro sinal (UA mínimo, muitas contas no IP), passa a **Challenge** ou **Block**.

**Com nginx (recomendado).** O módulo [geoip2](https://github.com/leev/ngx_http_geoip2_module) (`libnginx-mod-http-geoip2` no Debian/Ubuntu) consulta uma base `.mmdb` local (DB-IP Lite, IPinfo Lite ou MaxMind GeoLite2) e entrega o país à aplicação numa variável **sem o prefixo `HTTP_`** — que o cliente não tem como forjar, já que todo cabeçalho chega com esse prefixo:

```nginx
# http { }
geoip2 /var/lib/geoip/dbip-country-lite.mmdb {
    $geoip2_country country iso_code;
}

# location que repassa ao uWSGI (ou fastcgi_param / proxy_set_header no gunicorn)
uwsgi_param GEOIP_COUNTRY_CODE $geoip2_country;
```

```python
RISK_GUARDIAN = {
    "GEO_COUNTRY_META_KEY": "GEOIP_COUNTRY_CODE",
    "GEO_ALLOWED_COUNTRIES": ["BR"],
}
```

Com gunicorn atrás de `proxy_pass` não existe variável fora do `HTTP_`: o nginx precisa sobrescrever o cabeçalho (`proxy_set_header X-Geo-Country $geoip2_country;`) e a chave vira `HTTP_X_GEO_COUNTRY`, lida só de `TRUSTED_PROXIES`.

**Com Cloudflare.** A chave `HTTP_CF_IPCOUNTRY` é um cabeçalho, então só é lida quando o `REMOTE_ADDR` está em `TRUSTED_PROXIES` (as faixas do Cloudflare). Se o nginx reescreve o `REMOTE_ADDR` com `real_ip`, a origem do Cloudflare já não aparece para o Django: nesse caso passe o país pelo nginx, como acima, usando `$http_cf_ipcountry`.

### EmailAnalyzer (login e cadastro)

O `EmailAnalyzer` **não é um analyzer de middleware** — não roda por requisição e não entra na lista `ANALYZERS`. Ele avalia o **endereço de e-mail** nos signals de autenticação do Django (`user_logged_in` e `user_login_failed`) e é registrado automaticamente quando `risk_guardian` está em `INSTALLED_APPS`. Nenhuma configuração necessária.

Diferente dos analyzers de middleware, que retornam um único sinal, ele pode retornar vários de uma vez — todos somados ao `request.risk`:

| Reason | Delta | Detecta |
|---|---|---|
| `disposable_email` | +40 | Domínio descartável (mailinator, guerrillamail, yopmail, 10minutemail, ...) |
| `suspicious_email_hex_suffix` | +30 | Sufixo hexadecimal longo no local part (ex: `user4f3a9b2c1d@...`) |
| `suspicious_email_entropy` | +30 | Entropia de Shannon ≥ 3.5 — local part aparentemente gerado por máquina |
| `suspicious_email_digits` | +25 | Proporção de dígitos ≥ 50% no local part |

**Ordem de execução importa.** O login acontece dentro da view, ou seja, *depois* que o middleware já decidiu bloquear ou não. Os deltas de e-mail elevam `request.risk.score` durante a requisição, mas não disparam bloqueio retroativo. Cabe à view reler o score após o login:

```python
from django.contrib.auth import login

def view_de_login(request):
    login(request, user)   # dispara user_logged_in → EmailAnalyzer

    if request.risk.score >= 80:
        return redirect("verificacao_manual")
```

Para reagir ao evento, use o signal `email_risk_assessed`:

```python
from django.dispatch import receiver
from risk_guardian.signals import email_risk_assessed

@receiver(email_risk_assessed)
def alertar_cadastro_suspeito(sender, request, user, email, score, reasons, **kwargs):
    SlackNotifier.send(f"Login suspeito: {user.pk} (score={score}, {reasons})")
```

Os receivers automáticos usam os limiares padrão. Para ajustá-los, instancie o analyzer diretamente no seu próprio handler:

```python
from risk_guardian.analyzers import EmailAnalyzer

analyzer = EmailAnalyzer(
    digit_ratio_threshold=0.5,     # proporção de dígitos no local part
    entropy_threshold=3.5,         # entropia de Shannon
    min_length_for_entropy=8,      # tamanho mínimo para avaliar entropia
    hex_suffix_threshold=10,       # tamanho do sufixo hex
)

analyzer.evaluate("user4f3a9b2c1d@mailinator.com")
# [(40, "disposable_email"), (30, "suspicious_email_hex_suffix")]
```

### Auditoria da base existente

O comando `audit_emails` aplica o `EmailAnalyzer` em todos os usuários já cadastrados — útil para encontrar contas criadas antes de o middleware entrar em produção:

```bash
python manage.py audit_emails
python manage.py audit_emails --format json --min-score 40
```

```
PK       Email                                         Score  Reasons
------------------------------------------------------------------------------
1042     user4f3a9b2c1d@mailinator.com                   100  disposable_email, suspicious_email_hex_suffix, suspicious_email_entropy
876      x7k2m9q4w1@guerrillamail.com                     65  disposable_email, suspicious_email_digits

Audited 12043 users, 2 flagged as suspicious.
```

Opções: `--format` (`table` ou `json`, padrão `table`) e `--min-score` (padrão `1`).

### Logs estruturados

O middleware emite JSON estruturado via logger `risk_guardian`:

```json
{
  "event": "ip_blocked",
  "mode": "enforce",
  "decision": "block",
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/accounts/login/",
  "request_id": "abc-123",
  "score": 85,
  "reasons": ["high_rate", "missing_ua"]
}
```

Eventos emitidos: `risk_assessed`, `ip_blocked`, `challenge_required`, `analyzer_error`, `email_risk_assessed`. O `path` vai sem a query string, que pode carregar tokens. O `request_id` vem do atributo `request.request_id` ou, sem ele, de `REQUEST_ID_META_KEY` — o mesmo id que o proxy grava no log de acesso, para cruzar os dois.

Os eventos `risk_assessed` e `challenge_required` são `INFO`: o projeto precisa encaminhar o logger `risk_guardian` nesse nível, senão só os `WARNING` (`ip_blocked`) aparecem:

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"risk_guardian": {"handlers": ["console"], "level": "INFO", "propagate": False}},
}
```

O evento `email_risk_assessed` loga apenas o **domínio** do e-mail, nunca o endereço completo.

### Decisões de design

**Nada assíncrono no caminho crítico.** O middleware roda de forma síncrona no ciclo da requisição e toda análise usa apenas o cache — nenhuma consulta ao banco, nenhuma chamada de rede externa, nenhuma task. A decisão de bloquear nunca depende de infraestrutura que possa estar lenta ou fora do ar. Persistência e notificação ficam a cargo dos signals, fora do caminho da decisão.

**Falha de analyzer nunca derruba a requisição.** Se um analyzer lança exceção, o middleware loga `analyzer_error`, ignora aquele analyzer e segue com os demais. Um bug no scoring degrada a detecção, não a disponibilidade da aplicação.

**Mecanismo público, configuração privada.** O algoritmo é aberto, mas os valores operacionais não. Seguindo o modelo do fail2ban e do ModSecurity: quem leu este repositório ainda não sabe quais são os seus thresholds reais, quais analyzers você deixou ativos, nem o histórico já acumulado do IP dele. O segredo operacional está na configuração do seu projeto, não no algoritmo — por isso todos os parâmetros são sobrescrevíveis via `RISK_GUARDIAN` e os defaults são apenas um ponto de partida razoável.

### Testes

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Com relatório de cobertura (o CI exige no mínimo 90%):

```bash
pytest tests/ --cov --cov-report=term-missing --cov-fail-under=90
```

---

## English

### What is it

A middleware that analyzes each HTTP request and assigns a **risk score (0–100)** from multiple behavioral signals: request rate, user-agent, session, navigation patterns, and timing. Weak signals alone block nothing — combined, they reveal automated or abusive behavior.

Bot detection is the most obvious application of the mechanism, not its limit. What the middleware delivers is a score your application uses to decide.

### How it works

```
Request → Analyzers → Risk Score → Policy → Allow / Monitor / Challenge / Block
```

Each analyzer contributes a delta and a reason. The composite score is compared against the configured thresholds and the decision is applied before the view runs.

### Decision bands

| Score | Decision | What happens |
|---|---|---|
| **0–19** | Allow | Request proceeds normally, no logging |
| **20–49** | Monitor | Proceeds normally, but emits a `risk_assessed` event for observability |
| **50–79** | Challenge | `request.risk.challenged = True` — the view decides (2FA, CAPTCHA, confirmation) |
| **80+** | Block | HTTP 429 and the IP is blocked for `BLOCK_TTL_SECONDS` |

Challenge and Block thresholds are configurable via `SCORE_THRESHOLD_CHALLENGE` and `SCORE_THRESHOLD_BLOCK`.

### Observe mode

With `"MODE": "observe"` the middleware scores the request and logs the decision it would take, but does not act: it never answers 429, writes no block to the cache (and ignores existing ones), does not set `request.risk.challenged` and does not send the `ip_blocked` and `challenge_required` signals. The decision is in `request.risk.decision` (`allow`, `monitor`, `challenge` or `block`) and in the `decision` field of the logs.

Use it when adding the package to a project already in production: after a week or two of real traffic, the events with `decision` `challenge` and `block` show what would be stopped, and the thresholds (or `ALLOWLIST_IPS`) are tuned before switching to `"enforce"`.

### Why Risk Guardian?

Each defense layer sees a different dimension of traffic:

| Technique | Detects |
|---|---|
| Rate limiting | Volume |
| CAPTCHA | Automation |
| IP blocking | Origin |
| WAF | Known patterns |
| **Risk Guardian** | **Composite behavior** |

**Risk Guardian complements these layers — it replaces none of them.** Keep your WAF, rate limiting, and CAPTCHA. What that stack is missing is a read on behavior: an IP with a medium rate + an outdated UA + no session on an authenticated path slips past each of those filters individually, yet is far more suspicious than any single one of those signals alone. Composite scoring captures exactly that.

### Use cases

- Bots and scrapers that stay within rate limits
- Distributed brute force
- Credential stuffing
- Vulnerability scanners (`.env`, `wp-admin`, probe paths)
- Anomalous browsing behavior (robotic timing, UA rotation)
- Abuse of expensive or sensitive endpoints

### Installation

```bash
pip install django-risk-guardian
```

```python
# settings.py
INSTALLED_APPS += ["risk_guardian"]

MIDDLEWARE = [
    # ...
    "django.contrib.sessions.middleware.SessionMiddleware",
    "risk_guardian.middleware.RiskGuardianMiddleware",  # after SessionMiddleware
    # ... other middlewares
]
```

The middleware must come **after** `SessionMiddleware`: before it, `request.session` does not exist and `SessionAnalyzer` sees no session at all.

### Client IP

By default the IP is `REMOTE_ADDR`, the only value the client cannot choose. Behind a reverse proxy, prefer fixing `REMOTE_ADDR` in the proxy itself (e.g. nginx `real_ip`). If you need to read a header, say which one and who may send it:

```python
RISK_GUARDIAN = {
    "CLIENT_IP_HEADER": "HTTP_X_FORWARDED_FOR",   # request.META key
    "TRUSTED_PROXIES": ["10.0.0.0/8"],            # who may set the header
}
```

The header is read only when the request comes from one of `TRUSTED_PROXIES`, and the client is the rightmost address that is not a trusted proxy. Trusting a header without that check lets an attacker pick their own IP: they dodge the block and can get the middleware to block someone else's IP.

IPs and networks in `ALLOWLIST_IPS` (CIDR accepted) are never scored nor blocked — useful for offices and front desks where many people share one IP.

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
    "MODE": "enforce",                    # or "observe" (see "Observe mode")
    "CACHE_BACKEND": "default",           # Django cache backend (should be Redis)
    "CACHE_PREFIX": "rg",
    "LOG_ALL_SCORES": False,
    "REQUEST_ID_META_KEY": "HTTP_X_REQUEST_ID",  # request id in the logs

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

    # Client IP (see "Client IP")
    "CLIENT_IP_HEADER": None,
    "TRUSTED_PROXIES": [],
    "ALLOWLIST_IPS": [],

    # Scan paths added to PatternAnalyzer's list
    "EXTRA_SCAN_PATHS": [],

    # Logins and signups per IP (AuthAnalyzer)
    "AUTH_WINDOW_SECONDS": 3600,
    "AUTH_ACCOUNTS_MONITOR": 3,
    "AUTH_ACCOUNTS_CHALLENGE": 5,
    "AUTH_FAILED_ACCOUNTS_CHALLENGE": 3,
    "AUTH_FAILED_ACCOUNTS_BLOCK": 5,
    "AUTH_SIGNUPS_CHALLENGE": 3,

    # Country of the request (GeoAnalyzer)
    "GEO_COUNTRY_META_KEY": None,
    "GEO_ALLOWED_COUNTRIES": [],
    "GEO_UNEXPECTED_COUNTRY_SCORE": 25,
    "GEO_TOR_SCORE": 40,

    # Active analyzers (order matters)
    "ANALYZERS": [
        "risk_guardian.analyzers.RateAnalyzer",
        "risk_guardian.analyzers.UserAgentAnalyzer",
        "risk_guardian.analyzers.SessionAnalyzer",
        "risk_guardian.analyzers.PatternAnalyzer",
        "risk_guardian.analyzers.TimingAnalyzer",
        "risk_guardian.analyzers.AuthAnalyzer",
        "risk_guardian.analyzers.GeoAnalyzer",
    ],
}
```

### Cache keys

All keys use the configured `CACHE_PREFIX` (default `rg`):

| Key | TTL | Contents |
|---|---|---|
| `{prefix}:hist:ip:{ip}` | `HISTORY_WINDOW_SECONDS` + 60 | Sliding history for the IP |
| `{prefix}:hist:sess:{session_key}` | `HISTORY_WINDOW_SECONDS` + 60 | Sliding history for the session |
| `{prefix}:blocked:{ip}` | `BLOCK_TTL_SECONDS` | Blocked-IP flag (checked before any analysis) |
| `{prefix}:sess_set:{ip}` | 300 | Set of distinct sessions seen for the IP |
| `{prefix}:auth:{ok\|fail\|signup}:{ip}` | `AUTH_WINDOW_SECONDS` + 60 | Accounts that logged in, failed or signed up from the IP (hashed, never the e-mail) |

Each history entry stores `ts`, `path`, `method`, `status`, `ua` (truncated to 100 chars) and `duration_ms`. The list is capped at `HISTORY_MAX_REQUESTS` entries.

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

Available signals: `ip_blocked`, `risk_assessed`, `challenge_required`, `email_risk_assessed`.

### Analyzers

| Analyzer | Detects | Max score | Emitted reasons |
|---|---|---|---|
| **RateAnalyzer** | Abnormal request volume per IP (from 5 samples on) | +50 | `critical_rate`, `high_rate`, `medium_rate` |
| **UserAgentAnalyzer** | Bot UAs, minimal UA (`Mozilla/5.0` with no platform), outdated browsers, missing UA | +40 | `bot_ua:curl`, `minimal_ua`, `missing_ua`, `outdated_browser` |
| **SessionAnalyzer** | Missing session, UA rotation, excessive sessions per IP | +35 | `no_session_on_auth_path`, `session_ua_rotation`, `excessive_sessions_per_ip` |
| **PatternAnalyzer** | Scan paths (.env, wp-admin, admin panels), high error rate, path diversity | +60 | `scan_attempt:/.env`, `high_error_rate`, `excessive_path_diversity` |
| **TimingAnalyzer** | Artificially regular intervals between requests | +30 | `robotic_timing` |
| **AuthAnalyzer** | Many accounts logging in or failing from one IP, serial signups | +80 | `credential_stuffing`, `failed_logins_many_accounts`, `logins_many_accounts`, `logins_several_accounts`, `signup_velocity` |
| **GeoAnalyzer** | Country outside the allowed list, Tor network (country resolved by the web server or the CDN) | +40 | `unexpected_country:NL`, `tor_exit` |

### AuthAnalyzer (credential stuffing and automated signup)

Whoever tests a list of stolen e-mails and passwords tries once or twice per account, so per-account lockouts never fire. The signal is the number of **distinct accounts** one IP touches inside a window (`AUTH_WINDOW_SECONDS`, 1 h by default).

The bundled receivers record every login (`user_logged_in`), failure (`user_login_failed`) and, with django-allauth installed, signup (`user_signed_up`). Accounts are stored as a hash keyed with `SECRET_KEY` — the cache holds no e-mail or username.

| Situation for the IP, inside the window | Delta | Reason |
|---|---|---|
| 5+ accounts with failures (`AUTH_FAILED_ACCOUNTS_BLOCK`) | +80 | `credential_stuffing` |
| 3+ accounts with failures (`AUTH_FAILED_ACCOUNTS_CHALLENGE`) | +50 | `failed_logins_many_accounts` |
| 5+ distinct accounts (`AUTH_ACCOUNTS_CHALLENGE`) | +50 | `logins_many_accounts` |
| 3+ distinct accounts (`AUTH_ACCOUNTS_MONITOR`) | +20 | `logins_several_accounts` |
| 3+ signups (`AUTH_SIGNUPS_CHALLENGE`) | +50 | `signup_velocity` |

Failures weigh more than successes: in an office, ten people logging in from one IP rarely mistype the password of five different accounts; a stolen-password list fails on about half of them. On its own, the office reaches **Challenge** at most, never **Block**.

The login runs inside the view, after the middleware has decided. The receivers add the signal to that request's `request.risk` (the view can react right away) and `AuthAnalyzer` applies the accumulated signal to every following request from the IP — that is where the challenge or the block lands.

Custom login or signup flows can record events directly:

```python
from risk_guardian.auth_tracking import SIGNUP, record_auth_event

record_auth_event(request, SIGNUP, user.email)
```

`tests/test_attack_replay.py` replays a typical credential stuffing run — a stolen-password list, one or two attempts per account, about half of the passwords already changed and a bare `Mozilla/5.0` user agent: the IP takes one account and is blocked at the 15th second.

### GeoAnalyzer (country of the request)

`GeoAnalyzer` does no lookup: it reads the country code the web server or the CDN already resolved, from `request.META[GEO_COUNTRY_META_KEY]`. Without that key it does nothing.

| Situation | Delta | Reason |
|---|---|---|
| Country `T1` (Tor network, Cloudflare's code) | +40 (`GEO_TOR_SCORE`) | `tor_exit` |
| Country outside `GEO_ALLOWED_COUNTRIES` | +25 (`GEO_UNEXPECTED_COUNTRY_SCORE`) | `unexpected_country:XX` |
| Unknown country (`XX`, empty) or empty list | 0 | — |

On its own, an unexpected country stays at **Monitor**; added to another signal (minimal UA, many accounts on the IP) it reaches **Challenge** or **Block**.

**With nginx (recommended).** The [geoip2](https://github.com/leev/ngx_http_geoip2_module) module (`libnginx-mod-http-geoip2` on Debian/Ubuntu) looks up a local `.mmdb` database (DB-IP Lite, IPinfo Lite or MaxMind GeoLite2) and hands the country to the application in a variable **without the `HTTP_` prefix** — which the client cannot forge, since every header arrives with that prefix:

```nginx
# http { }
geoip2 /var/lib/geoip/dbip-country-lite.mmdb {
    $geoip2_country country iso_code;
}

# location that passes to uWSGI (or fastcgi_param / proxy_set_header for gunicorn)
uwsgi_param GEOIP_COUNTRY_CODE $geoip2_country;
```

```python
RISK_GUARDIAN = {
    "GEO_COUNTRY_META_KEY": "GEOIP_COUNTRY_CODE",
    "GEO_ALLOWED_COUNTRIES": ["BR"],
}
```

With gunicorn behind `proxy_pass` there is no variable outside `HTTP_`: nginx must overwrite the header (`proxy_set_header X-Geo-Country $geoip2_country;`) and the key becomes `HTTP_X_GEO_COUNTRY`, read only from `TRUSTED_PROXIES`.

**With Cloudflare.** `HTTP_CF_IPCOUNTRY` is a header, so it is read only when `REMOTE_ADDR` is in `TRUSTED_PROXIES` (Cloudflare's ranges). If nginx rewrites `REMOTE_ADDR` with `real_ip`, the Cloudflare origin is no longer visible to Django: pass the country through nginx instead, as above, using `$http_cf_ipcountry`.

### EmailAnalyzer (login and signup)

`EmailAnalyzer` is **not a middleware analyzer** — it doesn't run per request and doesn't belong in the `ANALYZERS` list. It evaluates the **email address** on Django's authentication signals (`user_logged_in` and `user_login_failed`) and is registered automatically when `risk_guardian` is in `INSTALLED_APPS`. No configuration required.

Unlike middleware analyzers, which return a single signal, it can return several at once — all added to `request.risk`:

| Reason | Delta | Detects |
|---|---|---|
| `disposable_email` | +40 | Disposable domain (mailinator, guerrillamail, yopmail, 10minutemail, ...) |
| `suspicious_email_hex_suffix` | +30 | Long hexadecimal suffix in the local part (e.g. `user4f3a9b2c1d@...`) |
| `suspicious_email_entropy` | +30 | Shannon entropy ≥ 3.5 — machine-generated-looking local part |
| `suspicious_email_digits` | +25 | Digit ratio ≥ 50% in the local part |

**Execution order matters.** Login happens inside the view — that is, *after* the middleware has already decided whether to block. Email deltas raise `request.risk.score` during the request, but do not trigger a retroactive block. It's up to the view to re-read the score after login:

```python
from django.contrib.auth import login

def login_view(request):
    login(request, user)   # fires user_logged_in → EmailAnalyzer

    if request.risk.score >= 80:
        return redirect("manual_verification")
```

To react to the event, use the `email_risk_assessed` signal:

```python
from django.dispatch import receiver
from risk_guardian.signals import email_risk_assessed

@receiver(email_risk_assessed)
def alert_suspicious_signup(sender, request, user, email, score, reasons, **kwargs):
    SlackNotifier.send(f"Suspicious login: {user.pk} (score={score}, {reasons})")
```

The auto-registered receivers use the default thresholds. To tune them, instantiate the analyzer directly in your own handler:

```python
from risk_guardian.analyzers import EmailAnalyzer

analyzer = EmailAnalyzer(
    digit_ratio_threshold=0.5,     # digit ratio in the local part
    entropy_threshold=3.5,         # Shannon entropy
    min_length_for_entropy=8,      # minimum length to evaluate entropy
    hex_suffix_threshold=10,       # hex suffix length
)

analyzer.evaluate("user4f3a9b2c1d@mailinator.com")
# [(40, "disposable_email"), (30, "suspicious_email_hex_suffix")]
```

### Auditing an existing user base

The `audit_emails` command applies `EmailAnalyzer` to all existing users — useful for finding accounts created before the middleware went to production:

```bash
python manage.py audit_emails
python manage.py audit_emails --format json --min-score 40
```

```
PK       Email                                         Score  Reasons
------------------------------------------------------------------------------
1042     user4f3a9b2c1d@mailinator.com                   100  disposable_email, suspicious_email_hex_suffix, suspicious_email_entropy
876      x7k2m9q4w1@guerrillamail.com                     65  disposable_email, suspicious_email_digits

Audited 12043 users, 2 flagged as suspicious.
```

Options: `--format` (`table` or `json`, default `table`) and `--min-score` (default `1`).

### Structured logs

The middleware emits structured JSON via the `risk_guardian` logger:

```json
{
  "event": "ip_blocked",
  "mode": "enforce",
  "decision": "block",
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/accounts/login/",
  "request_id": "abc-123",
  "score": 85,
  "reasons": ["high_rate", "missing_ua"]
}
```

Emitted events: `risk_assessed`, `ip_blocked`, `challenge_required`, `analyzer_error`, `email_risk_assessed`. `path` has no query string, which may carry tokens. `request_id` comes from the `request.request_id` attribute or, without it, from `REQUEST_ID_META_KEY` — the same id the proxy writes to its access log, so both can be matched.

`risk_assessed` and `challenge_required` are `INFO`: the project must route the `risk_guardian` logger at that level, or only `WARNING` events (`ip_blocked`) show up:

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {"risk_guardian": {"handlers": ["console"], "level": "INFO", "propagate": False}},
}
```

The `email_risk_assessed` event logs only the email **domain**, never the full address.

### Design decisions

**Nothing asynchronous on the critical path.** The middleware runs synchronously within the request cycle, and all analysis hits the cache only — no database queries, no external network calls, no tasks. The decision to block never depends on infrastructure that might be slow or down. Persistence and notification are left to signals, outside the decision path.

**An analyzer failure never takes down the request.** If an analyzer raises, the middleware logs `analyzer_error`, skips that analyzer and continues with the rest. A bug in scoring degrades detection, not your application's availability.

**Public mechanism, private configuration.** The algorithm is open; the operational values are not. Following the fail2ban and ModSecurity model: someone who has read this repository still doesn't know your actual thresholds, which analyzers you left enabled, or the history already accumulated for their IP. The operational secret lives in your project's configuration, not in the algorithm — which is why every parameter is overridable via `RISK_GUARDIAN` and the defaults are only a reasonable starting point.

### Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

With a coverage report (CI enforces a minimum of 90%):

```bash
pytest tests/ --cov --cov-report=term-missing --cov-fail-under=90
```

---

## License

MIT
