from __future__ import annotations

import json
from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command

# spam@mailinator.com            -> 40  [disposable_email]
# user4f3a9b2c1d@mailinator.com  -> 100 [disposable_email, hex_suffix, entropy]
CLEAN_EMAILS = ["john.doe@example.com", "maria.silva@gmail.com"]
DISPOSABLE_EMAIL = "spam@mailinator.com"
HIGH_RISK_EMAIL = "user4f3a9b2c1d@mailinator.com"


def _create_users(*emails):
    User = get_user_model()
    for i, email in enumerate(emails):
        User.objects.create_user(username=f"user{i}", email=email, password="x")  # noqa: S106


def _run(**options) -> str:
    out = StringIO()
    call_command("audit_emails", stdout=out, **options)
    return out.getvalue()


@pytest.mark.django_db
class TestAuditEmailsCommand:
    def test_clean_base_flags_nothing(self):
        _create_users(*CLEAN_EMAILS)
        output = _run()
        assert "Audited 2 users, 0 flagged as suspicious." in output

    def test_flags_disposable_email(self):
        _create_users(DISPOSABLE_EMAIL, *CLEAN_EMAILS)
        output = _run()
        assert DISPOSABLE_EMAIL in output
        assert "disposable_email" in output
        assert "Audited 3 users, 1 flagged as suspicious." in output

    def test_users_without_email_are_excluded_from_total(self):
        User = get_user_model()
        _create_users(DISPOSABLE_EMAIL)
        User.objects.create_user(username="noemail", email="", password="x")  # noqa: S106
        output = _run()
        assert "Audited 1 users, 1 flagged as suspicious." in output

    def test_empty_base(self):
        output = _run()
        assert "Audited 0 users, 0 flagged as suspicious." in output

    def test_table_output_has_header_when_results_exist(self):
        _create_users(DISPOSABLE_EMAIL)
        output = _run()
        assert "PK" in output
        assert "Score" in output
        assert "Reasons" in output

    def test_table_output_omits_header_when_no_results(self):
        _create_users(*CLEAN_EMAILS)
        output = _run()
        assert "Reasons" not in output

    def test_results_sorted_by_score_descending(self):
        _create_users(DISPOSABLE_EMAIL, HIGH_RISK_EMAIL)
        output = _run()
        assert output.index(HIGH_RISK_EMAIL) < output.index(DISPOSABLE_EMAIL)

    def test_json_output(self):
        _create_users(DISPOSABLE_EMAIL, *CLEAN_EMAILS)
        payload = json.loads(_run(format="json"))
        assert len(payload) == 1
        entry = payload[0]
        assert entry["email"] == DISPOSABLE_EMAIL
        assert entry["score"] == 40
        assert entry["reasons"] == ["disposable_email"]
        assert isinstance(entry["pk"], int)

    def test_json_output_empty_base(self):
        _create_users(*CLEAN_EMAILS)
        assert json.loads(_run(format="json")) == []

    def test_min_score_filters_lower_scores(self):
        _create_users(DISPOSABLE_EMAIL, HIGH_RISK_EMAIL)
        payload = json.loads(_run(format="json", min_score=50))
        assert [e["email"] for e in payload] == [HIGH_RISK_EMAIL]

    def test_min_score_above_all_results_flags_nothing(self):
        _create_users(DISPOSABLE_EMAIL, HIGH_RISK_EMAIL)
        output = _run(min_score=101)
        assert "Audited 2 users, 0 flagged as suspicious." in output

    def test_high_risk_email_accumulates_multiple_reasons(self):
        _create_users(HIGH_RISK_EMAIL)
        entry = json.loads(_run(format="json"))[0]
        assert entry["score"] == 100
        assert set(entry["reasons"]) == {
            "disposable_email",
            "suspicious_email_hex_suffix",
            "suspicious_email_entropy",
        }
