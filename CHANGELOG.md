# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
| v0.2 | `GeoAnalyzer` — score by country via the Cloudflare `cf_country` header |
| v0.2 | `TorExitAnalyzer` — check against the Tor exit node list |
| v0.3 | AbuseIPDB API integration |
| v0.3 | Optional persistence of block history to the database for auditing |
| v0.4 | Prometheus metrics |
| v0.4 | Pre-built Grafana dashboard (importable JSON) |

[0.1.1]: https://github.com/mupisystems/django-risk-guardian/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mupisystems/django-risk-guardian/releases/tag/v0.1.0
