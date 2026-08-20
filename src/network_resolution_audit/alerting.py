"""Optional alerting backends (syslog, webhook)."""

from __future__ import annotations

import logging
import logging.handlers
from typing import Any

# Configure global logger with debug output
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def send_syslog(
    findings: list[dict[str, Any]],
    *,
    facility: int = logging.handlers.SysLogHandler.LOG_USER,
    address: str | tuple[str, int] = "/dev/log",
) -> None:
    """Send findings as structured syslog messages."""
    if not findings:
        return

    try:
        handler = logging.handlers.SysLogHandler(address=address, facility=facility)
        syslog_logger = logging.getLogger("nra.syslog")
        syslog_logger.setLevel(logging.INFO)

        # Avoid duplicate handlers
        if not any(isinstance(h, logging.handlers.SysLogHandler) for h in syslog_logger.handlers):
            syslog_logger.addHandler(handler)

        syslog_logger.propagate = False

        for finding in findings:
            msg = (
                f"network-resolution-audit[{finding['severity']}] "
                f"ip={finding['ip']} expected={finding['expected_mac']} "
                f"observed={finding['observed_mac']} reason={finding['reason']}"
            )
            if finding["severity"] == "HIGH":
                syslog_logger.error(msg)
            else:
                syslog_logger.warning(msg)

        handler.close()
        syslog_logger.removeHandler(handler)
    except Exception as exc:
        logger.exception("Syslog delivery failed: %s", exc)


def send_webhook(
    findings: list[dict[str, Any]],
    url: str,
    *,
    timeout: float = 5.0,
) -> None:
    """POST findings as JSON to a webhook URL (Slack, Teams, custom, etc.)."""
    if not findings:
        return

    try:
        import requests
    except ImportError:
        logger.warning(
            "requests not installed – webhook skipped "
            "(pip install network-resolution-audit[alerting])"
        )
        return

    payload: dict[str, Any] = {
        "source": "network-resolution-audit",
        "findings": findings,
        "count": len(findings),
    }

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()
        logger.info("Webhook delivered to %s (%d findings)", url, len(findings))
    except Exception as exc:
        logger.exception("Webhook delivery failed: %s", exc)


def emit_findings(
    findings: list[dict[str, Any]],
    *,
    syslog: bool = False,
    webhook_url: str | None = None,
) -> None:
    """Dispatch findings to configured backends."""
    if syslog:
        send_syslog(findings)
    if webhook_url:
        send_webhook(findings, webhook_url)
