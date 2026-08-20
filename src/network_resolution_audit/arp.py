"""Robust neighbor table collection using iproute2 JSON output when available."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

MAC_PATTERN = re.compile(
    r"^(?P<mac>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})$"
)

VALID_STATES = {
    "REACHABLE",
    "STALE",
    "DELAY",
    "PROBE",
    "FAILED",
    "INCOMPLETE",
    "NOARP",
    "PERMANENT",
    "NONE",
}


def _run_ip_neigh_json() -> list[dict[str, Any]] | None:
    """Try modern JSON output first (iproute2 >= 4.0)."""
    try:
        result = subprocess.run(
            ["ip", "-j", "neigh"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        data = json.loads(result.stdout)
        if isinstance(data, list):
            return data
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ):
        return None
    return None


def _normalize_mac(raw: str | None) -> str:
    if not raw:
        return "unknown"
    if MAC_PATTERN.fullmatch(raw):
        return raw.lower()
    return "unknown"


def _normalize_state(raw: Any) -> str:
    if isinstance(raw, list) and raw:
        candidate = str(raw[0]).upper()
    else:
        candidate = str(raw or "unknown").upper()
    return candidate if candidate in VALID_STATES else "unknown"


def _parse_json_entries(raw: list[dict[str, Any]]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for item in raw:
        dst = item.get("dst")
        if not dst:
            continue
        try:
            ip_address = str(ipaddress.ip_address(dst))
        except ValueError:
            continue

        entries.append(
            {
                "ip": ip_address,
                "mac": _normalize_mac(item.get("lladdr")),
                "state": _normalize_state(item.get("state")),
                "dev": str(item.get("dev") or ""),
            }
        )
    return entries


def _parse_text_entries(stdout: str) -> list[dict[str, str]]:
    """Fallback text parser for older iproute2."""
    entries: list[dict[str, str]] = []
    for line in stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            ip_address = str(ipaddress.ip_address(parts[0]))
        except ValueError:
            continue

        mac_address = "unknown"
        state = "unknown"
        dev = ""

        i = 1
        while i < len(parts):
            part = parts[i]
            if part == "dev" and i + 1 < len(parts):
                dev = parts[i + 1]
                i += 2
                continue
            if MAC_PATTERN.fullmatch(part):
                mac_address = part.lower()
            elif part.upper() in VALID_STATES:
                state = part.upper()
            i += 1

        entries.append(
            {
                "ip": ip_address,
                "mac": mac_address,
                "state": state,
                "dev": dev,
            }
        )
    return entries


def get_neighbor_table() -> list[dict[str, str]]:
    """
    Return validated entries from the Linux neighbor table.

    Prefers ``ip -j neigh`` for robustness; falls back to classic text parsing.
    Raises RuntimeError on unrecoverable failures.
    """
    json_data = _run_ip_neigh_json()
    if json_data is not None:
        entries = _parse_json_entries(json_data)
        logger.debug("Parsed %d neighbor entries via JSON", len(entries))
        return entries

    try:
        result = subprocess.run(
            ["ip", "neigh"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "The `ip` command was not found. This tool currently targets Linux "
            "with iproute2 installed."
        ) from exc
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or "").strip() or "unknown error"
        raise RuntimeError(f"Unable to read neighbor table: {message}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Timed out while reading neighbor table") from exc

    entries = _parse_text_entries(result.stdout)
    logger.debug("Parsed %d neighbor entries via text fallback", len(entries))
    return entries
