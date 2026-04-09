from __future__ import annotations

import math
import re
from collections import Counter

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamail.net",
    "tempmail.com",
    "tempmail.net",
    "throwaway.email",
    "yopmail.com",
    "yopmail.fr",
    "sharklasers.com",
    "guerrillamailblock.com",
    "grr.la",
    "dispostable.com",
    "trashmail.com",
    "trashmail.me",
    "mailnesia.com",
    "maildrop.cc",
    "discard.email",
    "temp-mail.org",
    "fakeinbox.com",
    "tempinbox.com",
    "mohmal.com",
    "burnermail.io",
    "10minutemail.com",
    "minutemail.com",
    "emailondeck.com",
    "getnada.com",
    "mailsac.com",
    "harakirimail.com",
}


def _hex_suffix_length(local_part: str) -> int:
    """Return the length of the trailing hex-like suffix (digits + a-f)."""
    suffix_len = 0
    for c in reversed(local_part.lower()):
        if c in "0123456789abcdef":
            suffix_len += 1
        else:
            break
    return suffix_len


def _digit_ratio(local_part: str) -> float:
    if not local_part:
        return 0.0
    digits = sum(1 for c in local_part if c.isdigit())
    return digits / len(local_part)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class EmailAnalyzer:
    """
    Analyzes an email address for suspicious patterns.
    Not a middleware analyzer — used via signal handler on login/signup.
    """

    def __init__(
        self,
        digit_ratio_threshold: float = 0.5,
        entropy_threshold: float = 3.5,
        min_length_for_entropy: int = 8,
        hex_suffix_threshold: int = 10,
    ):
        self.digit_ratio_threshold = digit_ratio_threshold
        self.entropy_threshold = entropy_threshold
        self.min_length_for_entropy = min_length_for_entropy
        self.hex_suffix_threshold = hex_suffix_threshold

    def evaluate(self, email: str) -> list[tuple[int, str]]:
        """
        Returns a list of (delta, reason) tuples for all detected signals.
        Unlike middleware analyzers, this can return multiple signals at once.
        """
        signals: list[tuple[int, str]] = []

        if not email or "@" not in email:
            return signals

        local_part, domain = email.rsplit("@", 1)
        domain_lower = domain.lower()

        if domain_lower in DISPOSABLE_DOMAINS:
            signals.append((40, "disposable_email"))

        hex_len = _hex_suffix_length(local_part)
        if hex_len >= self.hex_suffix_threshold:
            signals.append((30, "suspicious_email_hex_suffix"))

        ratio = _digit_ratio(local_part)
        if ratio >= self.digit_ratio_threshold:
            signals.append((25, "suspicious_email_digits"))

        clean = re.sub(r"[.\-_+]", "", local_part)
        if len(clean) >= self.min_length_for_entropy:
            ent = _entropy(clean.lower())
            if ent >= self.entropy_threshold:
                signals.append((30, "suspicious_email_entropy"))

        return signals
