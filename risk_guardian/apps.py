from django.apps import AppConfig


class RiskGuardianConfig(AppConfig):
    name = "risk_guardian"
    verbose_name = "Risk Guardian"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        import risk_guardian.receivers  # noqa: F401
