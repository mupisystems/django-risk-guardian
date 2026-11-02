# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-02

Detects credential stuffing and automated signup, scores the country resolved
by the web server or the CDN, and stops trusting a client-supplied
`X-Real-IP` — **a breaking change** for projects that relied on it (see
Security).

### Security

- The client IP no longer comes from `X-Real-IP` unconditionally. A client
  could set that header to dodge a block or to get another IP blocked. The IP
  is now `REMOTE_ADDR`; a header is read only when `CLIENT_IP_HEADER` is set
  and the request comes from one of `TRUSTED_PROXIES`. **Projects that relied
  on `X-Real-IP` must set both** (or fix `REMOTE_ADDR` in the proxy).

### Added

- `MODE`: `"enforce"` (default) or `"observe"`. In observe mode the middleware
  scores and logs the decision it would take but never blocks, never sets
  `request.risk.challenged` and sends no `ip_blocked`/`challenge_required`
  signals — for calibrating thresholds on production traffic.
- `request.risk.decision` (`allow`, `monitor`, `challenge`, `block`) and, in
  every log event, `mode`, `decision`, `method` and `path` (without the query
  string). `request_id` falls back to `REQUEST_ID_META_KEY`
  (`HTTP_X_REQUEST_ID`), so events can be matched with the proxy's access log.
- `GeoAnalyzer`: scores the country the web server or the CDN resolved, read
  from `GEO_COUNTRY_META_KEY` — `unexpected_country:XX` outside
  `GEO_ALLOWED_COUNTRIES` and `tor_exit` for Cloudflare's `T1`. Does nothing
  until configured. A header key (`HTTP_*`) is read only from
  `TRUSTED_PROXIES`; the README shows nginx's geoip2 module passing the country
  in a variable the client cannot forge.
- `AuthAnalyzer`: scores an IP by the distinct accounts that logged in, failed
  to log in or signed up from it within `AUTH_WINDOW_SECONDS` — the signal of
  credential stuffing and automated signup. Enabled by default; thresholds in
  `AUTH_*` settings. Accounts are stored as a keyed hash, never in clear.
- Receivers that record logins, failed logins and, with django-allauth,
  signups; `record_auth_event()` for custom login and signup flows.
- `ALLOWLIST_IPS` (IPs and CIDR networks never scored nor blocked).
- `EXTRA_SCAN_PATHS` and more built-in scan paths (`/django-admin`,
  `/backoffice`, `/adminer`, `/administrator`, `/_ignition`, `/actuator`,
  `/xmlrpc.php`, `/.svn`, `/vendor/phpunit`).
- `minimal_ua` reason for a bare `Mozilla/5.0` user agent.
- Replay test of a typical credential stuffing run.

### Fixed

- `RateAnalyzer` no longer extrapolates a rate from fewer than 5 requests
  (`min_samples`): a form loaded and submitted one second apart read as
  120 requests per minute and scored `critical_rate`.
- README: the middleware goes after `SessionMiddleware`; placed first, it never
  sees the session.

## [0.1.1] - 2026-08-25

Documentation and testing release. No runtime changes — the `risk_guardian`
package is byte-for-byte identical to 0.1.0.

### Added

- Coverage job in CI, gated at 90%
- Tests for `decorators` and the `audit_emails` command, both previously
  at 0% coverage (suite: 70 → 97 tests, coverage: 82% → 95%)
- `pytest-cov` in the `dev` extra, plus coverage configuration

### Changed

- README rewritten: leads with behavior-based risk scoring rather than bot
  detection, and documents the decision bands, the `EmailAnalyzer`, the
  `audit_emails` command, cache keys and the design rationale — none of which
  were covered before

### Fixed

- `.gitignore` now excludes coverage and ruff artifacts

## [0.1.0] - 2026-04-08

### Added

- `RiskGuardianMiddleware` with composite risk scoring (0–100)
- `AccessHistory` with sliding-window tracking via Django cache
- 5 built-in analyzers: Rate, UserAgent, Session, Pattern, Timing
- `EmailAnalyzer` for login/signup risk: disposable domains, hex suffixes,
  high digit ratio and high-entropy local parts
- `RiskAssessment` dataclass attached to `request.risk`
- Signals: `ip_blocked`, `risk_assessed`, `challenge_required`,
  `email_risk_assessed`
- Decorators: `@require_risk_below`, `@require_no_challenge`
- `audit_emails` management command to scan an existing user base
- Configurable via `settings.RISK_GUARDIAN` dict with functional defaults
- Structured JSON logging for all risk events
- 70 tests covering analyzers, history, middleware and email analysis

## Roadmap

Planned, not yet implemented:

| Version | Feature |
|---|---|
| v0.3 | Per-account login context — new device or network for that user |
| v0.3 | Hosting and VPN ASNs as a signal |
| v0.3 | In-process `.mmdb` lookup for projects without geoip2 in the web server |
| v0.3 | Tor exit list for projects without Cloudflare (which already reports `T1`) |
| v0.3 | AbuseIPDB API integration |
| v0.3 | Optional persistence of block history to the database for auditing |
| v0.4 | Prometheus metrics |
| v0.4 | Pre-built Grafana dashboard (importable JSON) |

[0.2.0]: https://github.com/mupisystems/django-risk-guardian/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mupisystems/django-risk-guardian/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mupisystems/django-risk-guardian/releases/tag/v0.1.0
