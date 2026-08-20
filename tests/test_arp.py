"""Unit tests for neighbor table parsing."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from network_resolution_audit.arp import get_neighbor_table


class TestNeighborTable:
    @patch("network_resolution_audit.arp.subprocess.run")
    def test_json_parsing(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout=json.dumps(
                [
                    {
                        "dst": "192.168.1.1",
                        "lladdr": "AA:BB:CC:DD:EE:FF",
                        "dev": "eth0",
                        "state": ["REACHABLE"],
                    },
                    {
                        "dst": "fe80::1",
                        "lladdr": "11:22:33:44:55:66",
                        "dev": "eth0",
                        "state": ["STALE"],
                    },
                ]
            ),
            returncode=0,
        )

        entries = get_neighbor_table()
        assert len(entries) == 2
        assert entries[0]["ip"] == "192.168.1.1"
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entries[0]["state"] == "REACHABLE"
        assert entries[0]["dev"] == "eth0"
        assert entries[1]["ip"] == "fe80::1"

    @patch("network_resolution_audit.arp._run_ip_neigh_json", return_value=None)
    @patch("network_resolution_audit.arp.subprocess.run")
    def test_text_fallback(self, mock_run: MagicMock, _json_mock: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout=(
                "192.168.1.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n"
                "192.168.1.10 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
                "not-an-ip dev eth0 lladdr bad REACHABLE\n"
            ),
            returncode=0,
        )

        entries = get_neighbor_table()
        assert len(entries) == 2
        assert entries[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert entries[0]["dev"] == "eth0"
        assert entries[1]["state"] == "STALE"
        assert entries[1]["dev"] == "eth0"

    @patch("network_resolution_audit.arp._run_ip_neigh_json", return_value=None)
    @patch("network_resolution_audit.arp.subprocess.run")
    def test_command_failure(self, mock_run: MagicMock, _json_mock: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["ip", "neigh"], stderr="permission denied"
        )
        with pytest.raises(RuntimeError, match="permission denied"):
            get_neighbor_table()

    @patch("network_resolution_audit.arp._run_ip_neigh_json", return_value=None)
    @patch("network_resolution_audit.arp.subprocess.run")
    def test_ip_not_found(self, mock_run: MagicMock, _json_mock: MagicMock) -> None:
        mock_run.side_effect = FileNotFoundError()
        with pytest.raises(RuntimeError, match="ip.*not found"):
            get_neighbor_table()

    @patch("network_resolution_audit.arp.subprocess.run")
    def test_invalid_mac_becomes_unknown(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            stdout=json.dumps(
                [
                    {
                        "dst": "192.168.1.1",
                        "lladdr": "not-a-mac",
                        "dev": "eth0",
                        "state": ["REACHABLE"],
                    }
                ]
            ),
            returncode=0,
        )
        entries = get_neighbor_table()
        assert entries[0]["mac"] == "unknown"
