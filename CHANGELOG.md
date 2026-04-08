# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-08

### Added

- `RiskGuardianMiddleware` with composite risk scoring (0–100)
- `AccessHistory` with sliding-window tracking via Django cache
- 5 built-in analyzers: Rate, UserAgent, Session, Pattern, Timing
- `RiskAssessment` dataclass attached to `request.risk`
- Signals: `ip_blocked`, `risk_assessed`, `challenge_required`
- Decorators: `@require_risk_below`, `@require_no_challenge`
- Configurable via `settings.RISK_GUARDIAN` dict with functional defaults
- Structured JSON logging for all risk events
- 39 tests covering analyzers, history, and middleware
