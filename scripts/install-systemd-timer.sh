#!/usr/bin/env bash
# Install a simple systemd timer that runs network-resolution-audit every 10 minutes.
# Run as root (or with sudo).

set -euo pipefail

BIN="$(command -v network-resolution-audit || command -v nra || true)"
if [[ -z "$BIN" ]]; then
  echo "network-resolution-audit / nra not found in PATH. Install the package first."
  exit 1
fi

BASELINE_DIR="${BASELINE_DIR:-/etc/nra}"
REPORT_DIR="${REPORT_DIR:-/var/log/nra}"
INTERVAL="${INTERVAL:-10min}"

mkdir -p "$BASELINE_DIR" "$REPORT_DIR"

cat > /etc/systemd/system/network-resolution-audit.service <<EOF
[Unit]
Description=Network Resolution Audit
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN --baseline $BASELINE_DIR/baseline.json --report $REPORT_DIR/latest.json --ignore-missing --syslog
Nice=10
EOF

cat > /etc/systemd/system/network-resolution-audit.timer <<EOF
[Unit]
Description=Run Network Resolution Audit periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=$INTERVAL
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now network-resolution-audit.timer
echo "Installed and started network-resolution-audit.timer (every $INTERVAL)"
systemctl list-timers network-resolution-audit.timer
