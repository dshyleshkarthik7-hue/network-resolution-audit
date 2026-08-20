"""Unit tests for baseline load / save / compare."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from network_resolution_audit.baseline import (
    compare_baseline,
    load_baseline,
    save_baseline,
)


class TestBaseline:
    def test_changed_mapping_is_reported(self) -> None:
        entries = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
        ]
        baseline = {"192.168.1.1": "11:22:33:44:55:66"}

        findings = compare_baseline(entries, baseline)

        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["observed_mac"] == "aa:bb:cc:dd:ee:ff"
        assert findings[0]["expected_mac"] == "11:22:33:44:55:66"

    def test_missing_mapping_is_reported(self) -> None:
        entries: list[dict[str, str]] = []
        baseline = {"192.168.1.1": "11:22:33:44:55:66"}

        findings = compare_baseline(entries, baseline)

        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["observed_mac"] == "missing"

    def test_ignore_missing(self) -> None:
        entries: list[dict[str, str]] = []
        baseline = {"192.168.1.1": "11:22:33:44:55:66"}

        findings = compare_baseline(entries, baseline, ignore_missing=True)
        assert findings == []

    def test_save_and_load_round_trip(self) -> None:
        entries = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "state": "REACHABLE"}
        ]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            save_baseline(entries, str(path))
            loaded = load_baseline(str(path))
            assert loaded == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

            # Verify metadata format
            data = json.loads(path.read_text())
            assert "meta" in data
            assert data["meta"]["format_version"] == 2
            assert "mappings" in data

    def test_legacy_flat_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.json"
            path.write_text('{"192.168.1.1": "aa:bb:cc:dd:ee:ff"}\n')
            loaded = load_baseline(str(path))
            assert loaded == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

    def test_invalid_mac_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"192.168.1.1": "gg:hh:ii:jj:kk:ll"}\n')
            with pytest.raises(ValueError, match="Invalid MAC"):
                load_baseline(str(path))

    def test_invalid_ip_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"not-an-ip": "aa:bb:cc:dd:ee:ff"}\n')
            with pytest.raises(ValueError, match="Invalid IP"):
                load_baseline(str(path))

    def test_matching_entry_no_finding(self) -> None:
        entries = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
        ]
        baseline = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
        findings = compare_baseline(entries, baseline)
        assert findings == []
