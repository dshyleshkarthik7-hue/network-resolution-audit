"""DNS forward and reverse lookup helpers with strict error isolation."""

from __future__ import annotations

import logging
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)

DNS_ERRORS = (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


def resolve_hostname(
    hostname: str,
    *,
    lifetime: float = 3.0,
) -> dict[str, Any]:
    """
    Resolve A and AAAA records for a hostname.

    Empty lists are returned for missing records or expected resolver failures.
    Unexpected exceptions are captured in the ``error`` field.
    """
    results: dict[str, Any] = {
        "hostname": hostname,
        "A": [],
        "AAAA": [],
        "error": None,
    }

    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=lifetime,
            )
            results[record_type] = sorted({answer.to_text() for answer in answers})
        except DNS_ERRORS as exc:
            logger.debug(
                "DNS %s lookup for %s failed: %s", record_type, hostname, exc
            )
            results[record_type] = []
        except Exception as exc:  # pragma: no cover – unexpected
            logger.warning(
                "Unexpected DNS error for %s/%s: %s", hostname, record_type, exc
            )
            results["error"] = str(exc)

    return results


def reverse_lookup(
    ip_address: str,
    *,
    lifetime: float = 3.0,
) -> list[str]:
    """
    Return PTR names for an IPv4 or IPv6 address.
    Returns empty list on any failure (including invalid IP).
    """
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(
            reverse_name,
            "PTR",
            lifetime=lifetime,
        )
        return sorted({answer.to_text().rstrip(".") for answer in answers})
    except (*DNS_ERRORS, ValueError, dns.exception.SyntaxError) as exc:
        logger.debug("Reverse lookup for %s failed: %s", ip_address, exc)
        return []
