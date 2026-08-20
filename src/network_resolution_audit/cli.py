"""Command-line interface for network-resolution-audit."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table

from network_resolution_audit import __version__
from network_resolution_audit.alerting import emit_findings
from network_resolution_audit.arp import get_neighbor_table
from network_resolution_audit.baseline import compare_baseline, load_baseline, save_baseline
from network_resolution_audit.dns import resolve_hostname, reverse_lookup
from network_resolution_audit.report import build_report, save_report

console = Console()
logger = logging.getLogger("network_resolution_audit")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _print_arp(entries: list[dict[str, str]]) -> None:
    table = Table(title="ARP / Neighbor Table", show_header=True, header_style="bold cyan")
    table.add_column("IP", style="green")
    table.add_column("MAC", style="yellow")
    table.add_column("State")
    table.add_column("Device")

    if not entries:
        console.print("[dim]No neighbor entries found.[/dim]")
        return

    for entry in entries:
        table.add_row(
            entry["ip"],
            entry["mac"],
            entry["state"],
            entry.get("dev", ""),
        )
    console.print(table)


def _print_findings(findings: list[dict[str, object]]) -> None:
    console.print()
    if not findings:
        console.print("[green]✓ No baseline deviations detected.[/green]")
        return

    table = Table(title="Security Findings", show_header=True, header_style="bold red")
    table.add_column("Severity", style="bold")
    table.add_column("IP")
    table.add_column("Expected → Observed")
    table.add_column("Reason")

    for f in findings:
        severity = str(f["severity"])
        color = "red" if severity == "HIGH" else "yellow"
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            str(f["ip"]),
            f"{f['expected_mac']} → {f['observed_mac']}",
            str(f["reason"]),
        )
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-resolution-audit",
        description=(
            "Passive Linux ARP/neighbor-table and DNS resolution auditor.\n"
            "Detects unexpected IP-to-MAC changes and performs simple DNS lookups.\n"
            "Designed for defensive monitoring – never injects traffic."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  network-resolution-audit
  network-resolution-audit --init-baseline
  network-resolution-audit --hostname example.com --hostname github.com
  network-resolution-audit --reverse 8.8.8.8 --syslog
  network-resolution-audit --baseline /etc/nra/baseline.json --report /var/log/nra/latest.json

Threat model notes:
  A changed MAC is a signal to investigate, not proof of an attack.
  Legitimate causes include DHCP reassignment, VM migration, device replacement,
  roaming clients, and stale neighbor entries.
""",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--hostname",
        action="append",
        default=[],
        metavar="HOST",
        help="Hostname to resolve (A + AAAA). May be repeated.",
    )
    parser.add_argument(
        "--reverse",
        action="append",
        default=[],
        metavar="IP",
        help="IP address for reverse (PTR) lookup. May be repeated.",
    )
    parser.add_argument(
        "--baseline",
        default="config/baseline.json",
        help="Path to IP-to-MAC baseline file (default: config/baseline.json)",
    )
    parser.add_argument(
        "--init-baseline",
        action="store_true",
        help="Create or overwrite the baseline from the current neighbor table",
    )
    parser.add_argument(
        "--ignore-missing",
        action="store_true",
        help="Do not report baseline entries that are currently absent (reduces DHCP churn noise)",
    )
    parser.add_argument(
        "--report",
        default="reports/latest.json",
        help="JSON report output path (default: reports/latest.json)",
    )
    parser.add_argument(
        "--syslog",
        action="store_true",
        help="Emit findings to local syslog",
    )
    parser.add_argument(
        "--webhook",
        metavar="URL",
        help="POST findings as JSON to the given webhook URL",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable rich color output",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        console.no_color = True

    _configure_logging(args.verbose)

    try:
        arp_entries = get_neighbor_table()
    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 2

    _print_arp(arp_entries)

    if args.init_baseline:
        save_baseline(arp_entries, args.baseline)
        console.print(f"\n[green]Baseline saved to:[/green] {args.baseline}")

    try:
        baseline = load_baseline(args.baseline)
    except ValueError as exc:
        console.print(f"[red]Baseline error:[/red] {exc}")
        return 3

    findings = compare_baseline(
        arp_entries,
        baseline,
        ignore_missing=args.ignore_missing,
    )
    _print_findings(findings)

    emit_findings(
        findings,
        syslog=args.syslog,
        webhook_url=args.webhook,
    )

    dns_results: list[dict[str, object]] = []
    if args.hostname:
        console.print("\n[bold]DNS Forward Lookups[/bold]")
        for hostname in args.hostname:
            result = resolve_hostname(hostname)
            dns_results.append(result)
            a_str = ", ".join(result["A"]) or "none"
            aaaa_str = ", ".join(result["AAAA"]) or "none"
            console.print(f"  {hostname}")
            console.print(f"    A   : {a_str}")
            console.print(f"    AAAA: {aaaa_str}")
            if result.get("error"):
                console.print(f"    [yellow]error: {result['error']}[/yellow]")

    if args.reverse:
        console.print("\n[bold]DNS Reverse Lookups[/bold]")
        for ip_address in args.reverse:
            names = reverse_lookup(ip_address)
            console.print(f"  {ip_address}: {', '.join(names) or 'no PTR record'}")

    report = build_report(
        arp_entries,
        dns_results,
        findings,
        tool_version=__version__,
    )
    save_report(report, args.report)
    console.print(f"\n[dim]Report written to: {args.report}[/dim]")

    if any(f["severity"] == "HIGH" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())