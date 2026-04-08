# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Instead, use [GitHub Security Advisories](https://github.com/mupisystems/django-risk-guardian/security/advisories/new) to report the vulnerability privately. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to understand and address the issue before any public disclosure.

## Scope

This project is a security middleware. Vulnerabilities in the following areas are especially critical:

- Bypass of risk scoring or blocking logic
- Cache poisoning or key collision attacks
- IP spoofing through header manipulation
- Denial of service via analyzer exploitation
