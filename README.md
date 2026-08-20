# Network Resolution Audit

**Production-grade passive Linux network resolution auditor**

[![CI](https://github.com/dshyleshkarthik7-hue/network-resolution-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/dshyleshkarthik7-hue/network-resolution-audit/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A defensive, zero-injection tool that monitors the local **neighbor table (ARP/ND)** against a trusted baseline and performs simple **DNS** lookups. Designed for security operations, incident response, and continuous compliance monitoring.

> **Important:** A changed MAC address is a *reason to investigate*, not proof of an ARP attack. DHCP churn, VM migration, device replacement, roaming clients, and stale entries are all legitimate causes.

---

## Threat Model

| Threat | How this tool helps | What it does **not** do |
|--------|---------------------|-------------------------|
| ARP spoofing / poisoning | Detects unexpected IP→MAC changes against a baseline | Does not actively probe or inject packets |
| Rogue device on L2 segment | New or changed mappings surface as HIGH findings | Does not perform network discovery scans |
| DNS poisoning / cache issues | Simple A/AAAA + PTR checks for known hosts | Does not validate DNSSEC or monitor recursive resolvers |
| DHCP churn / misconfiguration | MEDIUM findings for missing baseline entries; `--ignore-missing` reduces noise | Does not talk to DHCP servers |

```
┌─────────────┐     ip neigh / ip -j neigh     ┌──────────────────┐
│  Linux Host │ ──────────────────────────────►│ Neighbor Table   │
└─────────────┘                                └────────┬─────────┘
                                                        │
                                                        ▼
┌─────────────┐     load / compare              ┌──────────────────┐
│  Baseline   │ ◄──────────────────────────────│  compare_baseline│
│  (JSON)     │                                └────────┬─────────┘
└─────────────┘                                         │
                                                        ▼
                                               ┌──────────────────┐
                                               │ Findings (HIGH / │
                                               │ MEDIUM) + Report │
                                               └────────┬─────────┘
                                                        │
                          ┌─────────────────────────────┼─────────────────┐
                          ▼                             ▼                 ▼
                     JSON Report                   Syslog / Webhook   Exit code
                                                                     (0/1/2/3)
```

---

## Features

- **Robust neighbor collection** – prefers `ip -j neigh` (JSON), falls back to classic text parsing
- **Baseline management** – create, validate, and compare IP→MAC mappings with metadata
- **Severity model** – HIGH (MAC change), MEDIUM (missing entry)
- **DNS helpers** – A/AAAA forward + PTR reverse lookups
- **SIEM-friendly JSON reports** with schema version and summary status
- **Alerting** – local syslog and optional webhook (Slack / Teams / custom)
- **Clean exit codes** for monitoring scripts and systemd timers
- **Rich terminal output** with tables and color
- **Fully typed**, linted, and covered by unit tests + CI

---

## Requirements

- Linux with `iproute2`
- Python 3.9+
- Network access only required for optional DNS lookups

---

## Installation

### From source (recommended for development)

```bash
git clone https://github.com/dshyleshkarthik7-hue/network-resolution-audit.git
cd network-resolution-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,alerting]"
```

### As a user-level tool

```bash
pip install .
# or once published: pip install network-resolution-audit
```

After installation the commands `network-resolution-audit` and the short alias `nra` are available.

---

## Quick Start

```bash
# 1. Capture a trusted baseline (do this on a clean network)
nra --init-baseline

# 2. Run a normal audit
nra

# 3. Include DNS checks and write a report
nra --hostname gateway.local --hostname example.com --reverse 8.8.8.8

# 4. Reduce DHCP noise and send findings to syslog
nra --ignore-missing --syslog

# 5. Webhook alert (requires [alerting] extra)
nra --webhook https://hooks.slack.com/services/T.../B.../xxx
```

---

## CLI Reference

```
usage: network-resolution-audit [-h] [--version] [-v] [--hostname HOST]
                                [--reverse IP] [--baseline PATH]
                                [--init-baseline] [--ignore-missing]
                                [--report PATH] [--syslog] [--webhook URL]
                                [--no-color]

Options:
  --init-baseline     Create/overwrite baseline from current neighbor table
  --baseline PATH     Path to baseline JSON (default: config/baseline.json)
  --ignore-missing    Suppress MEDIUM findings for absent baseline entries
  --hostname HOST     Resolve A + AAAA (repeatable)
  --reverse IP        PTR lookup (repeatable)
  --report PATH       JSON report path (default: reports/latest.json)
  --syslog            Emit findings to local syslog
  --webhook URL       POST findings as JSON
  -v, --verbose       Debug logging
  --no-color          Disable rich colors
```

**Exit codes**

| Code | Meaning |
|------|---------|
| 0    | OK – no HIGH findings |
| 1    | HIGH findings present (MAC change) |
| 2    | Unable to read neighbor table |
| 3    | Baseline file invalid |

---

## Baseline Format

New baselines are written with metadata:

```json
{
  "meta": {
    "created_at": "2026-08-20T06:57:00+00:00",
    "created_by": "network-resolution-audit",
    "entry_count": 12,
    "format_version": 2
  },
  "mappings": {
    "192.168.1.1": "aa:bb:cc:dd:ee:ff",
    "fe80::1": "11:22:33:44:55:66"
  }
}
```

Legacy flat `{ "ip": "mac" }` files are still accepted for backward compatibility.

Treat the baseline as **trusted input**. Review it before using it in production.

---

## Enterprise Deployment Notes

- Store baselines under `/etc/nra/` and reports under `/var/log/nra/`.
- Run via systemd timer every 5–15 minutes.
- Ship `reports/*.json` to your SIEM (Filebeat, Fluent Bit, Vector, etc.).
- Use `--ignore-missing` on highly dynamic DHCP segments.
- Combine with an IDS by treating HIGH findings as pre-filters that raise priority of subsequent packet analysis.
- For multi-host fleets, keep a central copy of baselines and distribute via configuration management (Ansible, Puppet, etc.).

---

## Development

```bash
# Install with all extras
pip install -e ".[dev,alerting]"

# Lint
ruff check src tests

# Type check
mypy src

# Tests + coverage
pytest
```

CI runs on every push/PR against Python 3.9–3.12 (ruff + mypy + pytest + package build).

---

## Limitations

- Observes only the **local** neighbor table – no active scanning or packet injection.
- DNS lookups are deliberately simple; empty results are not treated as security findings.
- Currently Linux-only (relies on `iproute2`).
- No built-in continuous daemon mode (use systemd/cron + exit codes instead).

---

## License

MIT – see [LICENSE](LICENSE).

---

## Changelog

### 1.0.0 (2026-08-20)

- Initial production release
- JSON-first neighbor parsing with text fallback
- Metadata-aware baselines (v2) + legacy support
- Strict MAC validation (hex-checked)
- Rich CLI, syslog + webhook alerting
- Full type hints, unit tests, GitHub Actions CI
- SIEM-friendly report schema
