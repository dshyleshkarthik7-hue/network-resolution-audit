"""Unit tests for report generation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from network_resolution_audit.report import build_report, save_report


class TestReport:
    def test_build_report_ok(self) -> None:
        report = build_report(
            arp_entries=[{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}],
            dns_results=[],
            findings=[],
            tool_version="1.0.0",
        )
        assert report["schema_version"] == "1.0"
        assert report["tool"]["name"] == "network-resolution-audit"
        assert report["tool"]["version"] == "1.0.0"
        assert report["summary"]["status"] == "OK"
        assert report["summary"]["findings_high"] == 0

    def test_build_report_alert(self) -> None:
        findings = [
            {
                "ip": "192.168.1.1",
                "expected_mac": "aa:bb:cc:dd:ee:ff",
                "observed_mac": "11:22:33:44:55:66",
                "severity": "HIGH",
                "reason": "changed",
            }
        ]
        report = build_report([], [], findings)
        assert report["summary"]["status"] == "ALERT"
        assert report["summary"]["findings_high"] == 1

    def test_build_report_warn(self) -> None:
        findings = [
            {
                "ip": "192.168.1.1",
                "expected_mac": "aa:bb:cc:dd:ee:ff",
                "observed_mac": "missing",
                "severity": "MEDIUM",
                "reason": "gone",
            }
        ]
        report = build_report([], [], findings)
        assert report["summary"]["status"] == "WARN"

    def test_save_report(self) -> None:
        report = build_report([], [], [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sub" / "report.json"
            save_report(report, path)
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["summary"]["status"] == "OK"
