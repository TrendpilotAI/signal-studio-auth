"""
Tests for SSA-838 — trusted proxy X-Forwarded-For IP extraction.

Coverage:
  - Trusted proxy: XFF used, leftmost non-private IP returned
  - Untrusted peer: XFF header ignored entirely (spoofing prevented)
  - Missing XFF from trusted proxy: falls back to peer IP
  - All-private XFF chain: falls back to peer IP
  - Multiple proxies in XFF chain
  - Custom TRUSTED_PROXY_IPS env var
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from middleware.trusted_proxy import (
    get_real_client_ip,
    _reset_trusted_networks_cache,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(peer_ip: str, xff: str | None = None) -> MagicMock:
    """Build a minimal mock of a FastAPI Request."""
    req = MagicMock()
    req.client = MagicMock()
    req.client.host = peer_ip
    headers: dict[str, str] = {}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    req.headers = headers
    return req


@pytest.fixture(autouse=True)
def reset_cache(monkeypatch):
    """Reset the CIDR cache before every test so env changes take effect."""
    _reset_trusted_networks_cache()
    yield
    _reset_trusted_networks_cache()


# ---------------------------------------------------------------------------
# Trusted proxy tests
# ---------------------------------------------------------------------------

class TestTrustedProxy:
    def test_trusted_proxy_returns_public_xff_ip(self):
        """Peer is a trusted proxy → leftmost public XFF IP is returned."""
        req = _make_request(peer_ip="10.0.0.1", xff="8.8.4.4, 10.0.0.1")
        assert get_real_client_ip(req) == "8.8.4.4"

    def test_trusted_proxy_single_xff_entry(self):
        """Single entry in XFF from trusted proxy."""
        req = _make_request(peer_ip="172.16.5.10", xff="1.2.3.4")
        assert get_real_client_ip(req) == "1.2.3.4"

    def test_trusted_proxy_skips_private_xff_ips_and_returns_public(self):
        """Multiple private IPs in XFF chain before the real public IP."""
        req = _make_request(
            peer_ip="192.168.1.1",
            xff="192.168.1.100, 10.10.10.10, 8.8.8.8, 10.0.0.2",
        )
        assert get_real_client_ip(req) == "8.8.8.8"

    def test_trusted_proxy_no_xff_falls_back_to_peer(self):
        """Trusted proxy but no XFF header → return peer IP directly."""
        req = _make_request(peer_ip="10.0.0.2", xff=None)
        assert get_real_client_ip(req) == "10.0.0.2"

    def test_trusted_proxy_empty_xff_falls_back_to_peer(self):
        """Empty XFF value from trusted proxy → return peer IP."""
        req = _make_request(peer_ip="10.0.0.3", xff="   ")
        assert get_real_client_ip(req) == "10.0.0.3"

    def test_trusted_proxy_all_private_xff_falls_back_to_peer(self):
        """All XFF addresses are private → fall back to peer."""
        req = _make_request(peer_ip="10.1.1.1", xff="192.168.0.1, 10.2.2.2")
        assert get_real_client_ip(req) == "10.1.1.1"

    def test_trusted_proxy_loopback_in_xff_skipped(self):
        """Loopback address in XFF is skipped in favour of next public IP."""
        req = _make_request(peer_ip="10.0.0.5", xff="127.0.0.1, 93.184.216.34")
        assert get_real_client_ip(req) == "93.184.216.34"


# ---------------------------------------------------------------------------
# Untrusted proxy (spoofing) tests
# ---------------------------------------------------------------------------

class TestUntrustedProxy:
    def test_untrusted_peer_xff_ignored(self):
        """Attacker sends XFF with loopback — must be ignored; real peer returned."""
        req = _make_request(peer_ip="203.0.113.99", xff="127.0.0.1")
        assert get_real_client_ip(req) == "203.0.113.99"

    def test_untrusted_peer_xff_with_spoofed_private_ip_ignored(self):
        """Attacker tries to appear as private IP to bypass rate limits."""
        req = _make_request(peer_ip="198.51.100.10", xff="10.0.0.1, 192.168.0.1")
        assert get_real_client_ip(req) == "198.51.100.10"

    def test_untrusted_peer_xff_with_spoofed_public_ip_ignored(self):
        """Attacker spoofs another client's public IP."""
        req = _make_request(peer_ip="45.33.32.156", xff="1.2.3.4")
        assert get_real_client_ip(req) == "45.33.32.156"

    def test_untrusted_peer_no_xff_returns_peer(self):
        """No XFF, untrusted peer → peer address returned normally."""
        req = _make_request(peer_ip="8.8.4.4", xff=None)
        assert get_real_client_ip(req) == "8.8.4.4"


# ---------------------------------------------------------------------------
# Missing / None client tests
# ---------------------------------------------------------------------------

class TestMissingClient:
    def test_no_client_object_returns_unknown(self):
        """request.client is None → return 'unknown'."""
        req = MagicMock()
        req.client = None
        req.headers = {}
        assert get_real_client_ip(req) == "unknown"


# ---------------------------------------------------------------------------
# Custom TRUSTED_PROXY_IPS env var
# ---------------------------------------------------------------------------

class TestCustomTrustedProxyEnv:
    def test_custom_cidr_trusted(self, monkeypatch):
        """Custom TRUSTED_PROXY_IPS: peer in custom CIDR trusts XFF."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "203.0.113.0/24")
        _reset_trusted_networks_cache()
        req = _make_request(peer_ip="203.0.113.5", xff="9.9.9.9")
        assert get_real_client_ip(req) == "9.9.9.9"

    def test_custom_cidr_untrusted_peer_ignored(self, monkeypatch):
        """Peer outside custom CIDR → XFF ignored."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "203.0.113.0/24")
        _reset_trusted_networks_cache()
        req = _make_request(peer_ip="10.0.0.1", xff="9.9.9.9")
        # 10.0.0.1 is NOT in 203.0.113.0/24, so XFF must be ignored
        assert get_real_client_ip(req) == "10.0.0.1"

    def test_malformed_cidr_ignored(self, monkeypatch):
        """Malformed CIDR entries are skipped without crashing."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "not-a-cidr,10.0.0.0/8")
        _reset_trusted_networks_cache()
        req = _make_request(peer_ip="10.0.0.2", xff="5.5.5.5")
        assert get_real_client_ip(req) == "5.5.5.5"
