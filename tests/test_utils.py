"""
test_utils.py — unit tests for get_client_ip (utils.py).

Pure-function tests against a minimal fake Request, no DB/HTTP client
needed. Uses pytest's monkeypatch fixture to flip settings.trusted_proxies
per test (auto-restored afterward) rather than the app-wide TESTING env,
since this behavior is independent of the rest of the test harness.
"""

from unittest.mock import MagicMock

import pytest

from utils import get_client_ip


def _fake_request(peer: str | None, xff: str | None = None):
    req = MagicMock()
    req.client.host = peer
    if peer is None:
        req.client = None
    req.headers.get = lambda key, default='': (xff if key == 'X-Forwarded-For' else default) or default
    return req


class TestGetClientIpUntrusted:
    """Default config: trusted_proxies is empty — XFF must never be honored."""

    def test_no_trusted_proxies_ignores_xff(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '')
        req = _fake_request('1.2.3.4', xff='9.9.9.9')
        assert get_client_ip(req) == '1.2.3.4'

    def test_no_client_returns_none(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '')
        req = _fake_request(None)
        assert get_client_ip(req) is None


class TestGetClientIpTrusted:
    """trusted_proxies configured — XFF honored only from a trusted peer."""

    def test_untrusted_peer_ignores_xff_even_when_some_proxies_trusted(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.16.0.0/12')
        # Peer is a public IP, not in the trusted range — header must be ignored.
        req = _fake_request('203.0.113.5', xff='9.9.9.9')
        assert get_client_ip(req) == '203.0.113.5'

    def test_trusted_peer_uses_rightmost_untrusted_hop(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.16.0.0/12')
        # nginx (172.20.0.5, trusted) forwarded a chain where a client tried
        # to prepend a spoofed IP to the left — the real client is the
        # right-most entry that isn't itself a trusted proxy.
        req = _fake_request('172.20.0.5', xff='9.9.9.9, 203.0.113.7')
        assert get_client_ip(req) == '203.0.113.7'

    def test_trusted_peer_single_hop(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.16.0.0/12')
        req = _fake_request('172.20.0.5', xff='203.0.113.9')
        assert get_client_ip(req) == '203.0.113.9'

    def test_trusted_peer_no_xff_header_falls_back_to_peer(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.16.0.0/12')
        req = _fake_request('172.20.0.5', xff=None)
        assert get_client_ip(req) == '172.20.0.5'

    def test_all_hops_trusted_falls_back_to_peer(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.16.0.0/12')
        # Every hop in the chain is itself inside the trusted range —
        # nothing more specific to report than the immediate peer.
        req = _fake_request('172.20.0.5', xff='172.20.0.1, 172.21.0.1')
        assert get_client_ip(req) == '172.20.0.5'

    def test_malformed_xff_entry_is_skipped_not_trusted(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.16.0.0/12')
        req = _fake_request('172.20.0.5', xff='not-an-ip')
        # An unparseable entry can't be confirmed trusted, so it's treated
        # as the (untrusted, therefore real) client-supplied value.
        assert get_client_ip(req) == 'not-an-ip'

    def test_malformed_trusted_proxies_config_entry_is_skipped(self, monkeypatch):
        monkeypatch.setattr('utils.settings.trusted_proxies',
                            'not-a-cidr, 172.16.0.0/12')
        req = _fake_request('172.20.0.5', xff='203.0.113.9')
        assert get_client_ip(req) == '203.0.113.9'

    def test_single_ip_trusted_proxy_entry_without_cidr(self, monkeypatch):
        # A bare IP (no /prefix) should work too, not just CIDR ranges.
        monkeypatch.setattr('utils.settings.trusted_proxies', '172.20.0.5')
        req = _fake_request('172.20.0.5', xff='203.0.113.9')
        assert get_client_ip(req) == '203.0.113.9'
