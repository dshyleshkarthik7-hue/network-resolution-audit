"""Unit tests for DNS helpers (mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver

from network_resolution_audit.dns import resolve_hostname, reverse_lookup


class TestDNS:
    @patch("network_resolution_audit.dns.dns.resolver.resolve")
    def test_resolve_hostname_success(self, mock_resolve: MagicMock) -> None:
        a_answer = MagicMock()
        a_answer.to_text.return_value = "93.184.216.34"
        aaaa_answer = MagicMock()
        aaaa_answer.to_text.return_value = "2606:2800:220:1:248:1893:25c8:1946"

        def side_effect(name: str, rdtype: str, lifetime: float = 3.0):
            if rdtype == "A":
                return [a_answer]
            if rdtype == "AAAA":
                return [aaaa_answer]
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = side_effect
        result = resolve_hostname("example.com")
        assert result["hostname"] == "example.com"
        assert result["A"] == ["93.184.216.34"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in result["AAAA"]
        assert result["error"] is None

    @patch("network_resolution_audit.dns.dns.resolver.resolve")
    def test_resolve_hostname_no_answer(self, mock_resolve: MagicMock) -> None:
        mock_resolve.side_effect = dns.resolver.NoAnswer()
        result = resolve_hostname("missing.example")
        assert result["A"] == []
        assert result["AAAA"] == []
        assert result["error"] is None

    @patch("network_resolution_audit.dns.dns.resolver.resolve")
    def test_reverse_lookup_success(self, mock_resolve: MagicMock) -> None:
        answer = MagicMock()
        answer.to_text.return_value = "dns.google."
        mock_resolve.return_value = [answer]
        names = reverse_lookup("8.8.8.8")
        assert names == ["dns.google"]

    @patch("network_resolution_audit.dns.dns.resolver.resolve")
    def test_reverse_lookup_failure(self, mock_resolve: MagicMock) -> None:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        names = reverse_lookup("192.0.2.1")
        assert names == []

    def test_reverse_lookup_invalid_ip(self) -> None:
        names = reverse_lookup("not-an-ip")
        assert names == []
