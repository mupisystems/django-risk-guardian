from __future__ import annotations

from unittest.mock import MagicMock

from risk_guardian.analyzers.email import (
    EmailAnalyzer,
    _digit_ratio,
    _entropy,
    _hex_suffix_length,
)
from risk_guardian.assessment import RiskAssessment


class TestDigitRatio:
    def test_all_digits(self):
        assert _digit_ratio("123456") == 1.0

    def test_no_digits(self):
        assert _digit_ratio("abcdef") == 0.0

    def test_mixed(self):
        assert _digit_ratio("abc123") == 0.5

    def test_empty(self):
        assert _digit_ratio("") == 0.0


class TestEntropy:
    def test_single_char(self):
        assert _entropy("aaaa") == 0.0

    def test_high_entropy(self):
        ent = _entropy("abcdefgh")
        assert ent > 2.5

    def test_empty(self):
        assert _entropy("") == 0.0


class TestHexSuffix:
    def test_pure_hex(self):
        assert _hex_suffix_length("abc123def456") == 12

    def test_name_with_hex_suffix(self):
        assert _hex_suffix_length("rafael65850e9aefcc") == 12

    def test_no_hex_suffix(self):
        assert _hex_suffix_length("joaosilva") == 1  # 'a' is a hex char

    def test_short_suffix(self):
        assert _hex_suffix_length("lucas123") == 3

    def test_empty(self):
        assert _hex_suffix_length("") == 0


class TestEmailAnalyzer:
    def test_clean_email_no_signals(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("lucas@gmail.com")
        assert signals == []

    def test_disposable_domain(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("test@mailinator.com")
        reasons = [r for _, r in signals]
        assert "disposable_email" in reasons

    def test_disposable_domain_case_insensitive(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("test@YOPMAIL.COM")
        reasons = [r for _, r in signals]
        assert "disposable_email" in reasons

    def test_high_digit_ratio(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("thiago6348630716a4@outlook.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_digits" in reasons

    def test_normal_digits_no_signal(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("lucas123@gmail.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_digits" not in reasons

    def test_high_entropy(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("qzxjvkwmrbtfhy@gmail.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_entropy" in reasons

    def test_normal_entropy_no_signal(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("joaosilva@gmail.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_entropy" not in reasons

    def test_hex_suffix_detected(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("rafael65850e9aefcc@mail.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_hex_suffix" in reasons

    def test_hex_suffix_catches_diluted_emails(self):
        """Emails where name dilutes digit ratio and entropy below thresholds."""
        analyzer = EmailAnalyzer()
        hard_cases = [
            "rafael65850e9aefcc@mail.com",
            "fernanda89880ddf412f@outlook.com",
            "camila15818ebafa81@hotmail.com",
            "fernanda22525d25f05e@mail.com",
        ]
        for email in hard_cases:
            signals = analyzer.evaluate(email)
            assert len(signals) > 0, f"{email} should be flagged"

    def test_no_hex_suffix_for_normal_email(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("lucas123@gmail.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_hex_suffix" not in reasons

    def test_multiple_signals(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("x8k3m9q2z7@tempmail.com")
        reasons = [r for _, r in signals]
        assert "disposable_email" in reasons
        assert len(signals) >= 2

    def test_empty_email(self):
        analyzer = EmailAnalyzer()
        assert analyzer.evaluate("") == []
        assert analyzer.evaluate("no-at-sign") == []

    def test_short_local_part_skips_entropy(self):
        analyzer = EmailAnalyzer()
        signals = analyzer.evaluate("ab1@gmail.com")
        reasons = [r for _, r in signals]
        assert "suspicious_email_entropy" not in reasons


class TestEmailReceivers:
    def test_login_signal_adds_risk(self):
        from risk_guardian.receivers import assess_email_on_login

        request = MagicMock()
        request.risk = RiskAssessment()
        user = MagicMock()
        user.email = "bot123456789@mailinator.com"

        assess_email_on_login(sender=None, request=request, user=user)

        assert request.risk.score > 0
        assert "disposable_email" in request.risk.reasons

    def test_login_signal_clean_email_no_change(self):
        from risk_guardian.receivers import assess_email_on_login

        request = MagicMock()
        request.risk = RiskAssessment()
        user = MagicMock()
        user.email = "lucas@gmail.com"

        assess_email_on_login(sender=None, request=request, user=user)

        assert request.risk.score == 0
        assert request.risk.reasons == []

    def test_login_signal_no_risk_attribute(self):
        from risk_guardian.receivers import assess_email_on_login

        request = MagicMock(spec=[])  # no 'risk' attribute
        user = MagicMock()
        user.email = "bot@mailinator.com"

        # Should not raise
        assess_email_on_login(sender=None, request=request, user=user)

    def test_failed_login_with_suspicious_email(self):
        from risk_guardian.receivers import track_failed_login

        request = MagicMock()
        request.risk = RiskAssessment()

        track_failed_login(
            sender=None,
            credentials={"username": "bot123456789@tempmail.com"},
            request=request,
        )

        assert request.risk.score > 0

    def test_failed_login_no_request(self):
        from risk_guardian.receivers import track_failed_login

        # Should not raise
        track_failed_login(
            sender=None,
            credentials={"username": "bot@tempmail.com"},
            request=None,
        )

    def test_login_emits_email_risk_assessed_signal(self):
        from risk_guardian.receivers import assess_email_on_login
        from risk_guardian.signals import email_risk_assessed

        handler = MagicMock()
        email_risk_assessed.connect(handler)

        try:
            request = MagicMock()
            request.risk = RiskAssessment()
            user = MagicMock()
            user.email = "x8k3m9q2z7@mailinator.com"

            assess_email_on_login(sender=None, request=request, user=user)

            assert handler.called
            call_kwargs = handler.call_args[1]
            assert call_kwargs["email"] == "x8k3m9q2z7@mailinator.com"
            assert call_kwargs["score"] > 0
        finally:
            email_risk_assessed.disconnect(handler)
