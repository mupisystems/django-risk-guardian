from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from risk_guardian.analyzers.email import EmailAnalyzer


class Command(BaseCommand):
    help = "Audit all user emails for suspicious patterns"

    def add_arguments(self, parser):
        parser.add_argument(
            "--format",
            choices=["table", "json"],
            default="table",
            help="Output format (default: table)",
        )
        parser.add_argument(
            "--min-score",
            type=int,
            default=1,
            help="Minimum score to include in results (default: 1)",
        )

    def handle(self, *args, **options):
        User = get_user_model()
        analyzer = EmailAnalyzer()
        output_format = options["format"]
        min_score = options["min_score"]

        results = []
        total = 0
        flagged = 0

        users = User.objects.exclude(email="").iterator(chunk_size=500)
        for user in users:
            total += 1
            signals = analyzer.evaluate(user.email)
            if not signals:
                continue

            score = sum(delta for delta, _ in signals)
            if score < min_score:
                continue

            flagged += 1
            reasons = [reason for _, reason in signals]
            results.append(
                {
                    "pk": user.pk,
                    "email": user.email,
                    "score": score,
                    "reasons": reasons,
                }
            )

        if output_format == "json":
            self.stdout.write(json.dumps(results, indent=2))
        else:
            if results:
                self.stdout.write(f"{'PK':<8} {'Email':<45} {'Score':>5}  Reasons")
                self.stdout.write("-" * 90)
                for r in sorted(results, key=lambda x: -x["score"]):
                    self.stdout.write(f"{r['pk']:<8} {r['email']:<45} {r['score']:>5}  {', '.join(r['reasons'])}")
            self.stdout.write(f"\nAudited {total} users, {flagged} flagged as suspicious.")
