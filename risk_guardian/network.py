from __future__ import annotations

import ipaddress
from functools import lru_cache

from risk_guardian.conf import get_config


@lru_cache(maxsize=32)
def _networks(entries: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(entry, strict=False) for entry in entries)


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def ip_in(ip: str, entries) -> bool:
    """True if ``ip`` falls in any of the IPs or CIDR networks in ``entries``."""
    if not entries:
        return False
    address = _parse_ip(ip)
    if address is None:
        return False
    return any(address in network for network in _networks(tuple(entries)))


def get_client_ip(request, config=None) -> str:
    """Return the client IP, trusting a proxy header only when it is safe.

    ``REMOTE_ADDR`` is the only value the client cannot choose. A header such as
    ``X-Forwarded-For`` or ``X-Real-IP`` is read only when ``CLIENT_IP_HEADER``
    is set *and* the request comes from one of ``TRUSTED_PROXIES``. In a
    comma-separated header the client is the rightmost address that is not a
    trusted proxy: everything to its left was written by the client and can be
    forged.
    """
    config = config or get_config()
    remote = request.META.get("REMOTE_ADDR") or "127.0.0.1"
    header = config["CLIENT_IP_HEADER"]
    trusted = config["TRUSTED_PROXIES"]
    if not header or not ip_in(remote, trusted):
        return remote

    candidates = [c.strip() for c in request.META.get(header, "").split(",") if c.strip()]
    for candidate in reversed(candidates):
        if _parse_ip(candidate) is None:
            return remote
        if not ip_in(candidate, trusted):
            return candidate
    return remote
