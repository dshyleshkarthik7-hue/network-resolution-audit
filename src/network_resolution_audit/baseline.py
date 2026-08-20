"""Baseline management with validation, rotation support and comparison logic."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAC_PATTERN = re.compile(
    r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$"
)


def _validate_mac(mac: str) -> str:
    """Normalize and validate a MAC address. Raises ValueError on invalid input."""
    normalized = mac.strip().lower()
    if normalized == "unknown":
        return normalized
    if not MAC_PATTERN.fullmatch(normalized):
        raise ValueError(f"Invalid MAC address: {mac}")
    return normalized


def load_baseline(path: str | Path) -> dict[str, str]:
    """
    Load an IP-to-MAC baseline.

    A missing file is treated as an empty baseline (no findings possible).
    Raises ValueError on malformed content.
    """
    baseline_path = Path(path)
    if not baseline_path.exists():
        logger.info("No baseline found at %s – treating as empty", path)
        return {}

    try:
        with baseline_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid baseline JSON: {exc}") from exc

    # Support both legacy flat format and metadata-wrapped format
    if isinstance(data, dict) and "mappings" in data:
        mappings = data["mappings"]
        meta = data.get("meta", {})
        logger.debug(
            "Loaded baseline created at %s by %s",
            meta.get("created_at"),
            meta.get("created_by", "unknown"),
        )
    else:
        mappings = data

    if not isinstance(mappings, dict):
        raise ValueError("Baseline mappings must be a JSON object.")

    baseline: dict[str, str] = {}
    for ip, mac in mappings.items():
        try:
            normalized_ip = str(ipaddress.ip_address(str(ip)))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address in baseline: {ip}") from exc

        if not isinstance(mac, str):
            raise ValueError(f"Invalid MAC address for {ip}.")

        baseline[normalized_ip] = _validate_mac(mac)

    return baseline


def save_baseline(
    entries: list[dict[str, str]],
    path: str | Path,
    *,
    created_by: str = "network-resolution-audit",
) -> None:
    """Save observed IP-to-MAC mappings as a baseline (metadata format v2)."""
    mappings: dict[str, str] = {}
    for entry in entries:
        ip = entry.get("ip")
        mac = entry.get("mac")
        if ip and mac and mac != "unknown":
            try:
                mappings[ip] = _validate_mac(mac)
            except ValueError:
                logger.warning("Skipping invalid MAC for %s: %s", ip, mac)

    payload = {
        "meta": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": created_by,
            "entry_count": len(mappings),
            "format_version": 2,
        },
        "mappings": mappings,
    }

    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    with baseline_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")

    logger.info("Baseline written to %s (%d mappings)", path, len(mappings))


def compare_baseline(
    entries: list[dict[str, str]],
    baseline: dict[str, str],
    *,
    ignore_missing: bool = False,
) -> list[dict[str, Any]]:
    """
    Report changed and (optionally) missing mappings.

    Severity model:
      - HIGH   : IP present with different MAC (possible ARP spoof / device change)
      - MEDIUM : Baseline entry no longer visible (common with DHCP churn / sleep)
    """
    findings: list[dict[str, Any]] = []
    observed: dict[str, str] = {}

    for entry in entries:
        ip = entry["ip"]
        current_mac = entry["mac"]
        if current_mac == "unknown":
            continue

        normalized_mac = current_mac.lower()
        observed[ip] = normalized_mac
        expected_mac = baseline.get(ip)

        if expected_mac and normalized_mac != expected_mac.lower():
            findings.append(
                {
                    "ip": ip,
                    "expected_mac": expected_mac,
                    "observed_mac": normalized_mac,
                    "severity": "HIGH",
                    "reason": (
                        "IP-to-MAC mapping differs from the trusted baseline. "
                        "Investigate device replacement, VM migration, or possible ARP spoofing."
                    ),
                    "dev": entry.get("dev", ""),
                }
            )

    if not ignore_missing:
        for ip, expected_mac in baseline.items():
            if ip not in observed:
                findings.append(
                    {
                        "ip": ip,
                        "expected_mac": expected_mac,
                        "observed_mac": "missing",
                        "severity": "MEDIUM",
                        "reason": (
                            "Baseline entry is not currently present in the neighbor table. "
                            "Common causes: device offline, DHCP lease expired, or interface down."
                        ),
                        "dev": "",
                    }
                )

    return findings
