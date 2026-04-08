from django.dispatch import Signal

ip_blocked = Signal()
risk_assessed = Signal()
challenge_required = Signal()
