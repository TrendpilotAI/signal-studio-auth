"""
Trusted-proxy middleware helper — SSA-838.

Provides get_real_client_ip(request) which safely extracts the originating
client IP from the X-Forwarded-For header **only** when the direct TCP peer
is a known/trusted proxy.  When the peer is untrusted (or not in the
TRUSTED_PROXY_IPS CIDR list) the raw peer address is returned directly,
preventing header-spoofing attacks against the rate limiter.

Configuration
-------------
TRUSTED_PROXY_IPS  Comma-separated list of CIDR blocks whose IPs are allowed
                   to set X-Forwarded-For.
                   Default: 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
                   (covers RFC-1918 private ranges used by Railway, K8s, etc.)
"""

from __future__ import annotations

import ipaddress
import os
from typing import List

from fastapi import Request

# ---------------------------------------------------------------------------
# CIDR list — loaded once at import time from the environment variable.
# ---------------------------------------------------------------------------

_DEFAULT_CIDRS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

_TRUSTED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []


def _load_trusted_networks(raw: str) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass  # skip malformed entries
    return networks


def _get_trusted_networks() -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Return the cached list, building it lazily on first access."""
    global _TRUSTED_NETWORKS
    if not _TRUSTED_NETWORKS:
        raw = os.environ.get("TRUSTED_PROXY_IPS", _DEFAULT_CIDRS)
        _TRUSTED_NETWORKS = _load_trusted_networks(raw)
    return _TRUSTED_NETWORKS


# Expose for testing — allows resetting the cache after env changes.
def _reset_trusted_networks_cache() -> None:
    global _TRUSTED_NETWORKS
    _TRUSTED_NETWORKS = []


# ---------------------------------------------------------------------------
# Private IP detection helpers
# ---------------------------------------------------------------------------

def _is_private(addr: str) -> bool:
    """Return True if *addr* is a private/loopback/link-local address."""
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _is_trusted_peer(peer_ip: str) -> bool:
    """Return True if *peer_ip* falls within a TRUSTED_PROXY_IPS CIDR."""
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(addr in net for net in _get_trusted_networks())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_real_client_ip(request: Request) -> str:
    """Return the real originating client IP for *request*.

    Algorithm
    ---------
    1. Read the direct TCP peer address (``request.client.host``).
    2. If the peer is **not** in TRUSTED_PROXY_IPS, return it as-is
       (X-Forwarded-For cannot be trusted — it may be attacker-supplied).
    3. If the peer **is** trusted, walk the X-Forwarded-For chain left-to-right
       and return the first non-private, non-loopback address found.
    4. If every address in XFF is private (or XFF is absent), fall back to
       the peer address.
    """
    peer = request.client.host if request.client else "unknown"

    if not _is_trusted_peer(peer):
        # Untrusted peer — ignore any X-Forwarded-For header entirely.
        return peer

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if not forwarded_for.strip():
        return peer

    for candidate in forwarded_for.split(","):
        candidate = candidate.strip()
        if candidate and not _is_private(candidate):
            return candidate

    # All XFF entries were private — fall back to the peer.
    return peer
