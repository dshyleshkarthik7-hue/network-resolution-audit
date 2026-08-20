"""JSON report generation with summary and optional SIEM-friendly structure."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def build_report(
    arp_entries: list[dict[str, str]],
    dns_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    tool_version: str = "1.0.0",
) -> dict[str, Any]:
    """Build a complete, SIEM-friendly audit report."""
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    return {
        "schema_version": "1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool": {
            "name": "network-resolution-audit",
            "version": tool_version,
        },
        "arp": arp_entries,
        "dns": dns_results,
        "findings": findings,
        "summary": {
            "arp_entries": len(arp_entries),
            "dns_queries": len(dns_results),
            "findings_total": len(findings),
            "findings_high": high,
            "findings_medium": medium,
            "status": "ALERT" if high > 0 else ("WARN" if medium > 0 else "OK"),
        },
    }


def save_report(report: dict[str, Any], output_path: str | Path) -> None:
    """Write report to JSON (creates parent directories)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    logger.info("Report written to %s", path)
