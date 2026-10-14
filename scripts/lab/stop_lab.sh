#!/usr/bin/env bash
# Stop the lab agents to free RAM. Data already in the SIEMs is kept.
# Run:     sudo bash scripts/lab/stop_lab.sh
# Restart: sudo systemctl start metricbeat wazuh-agent
set -uo pipefail

[ "$(id -u)" = 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }

for svc in metricbeat wazuh-agent; do
  if systemctl list-unit-files "$svc.service" 2>/dev/null | grep -q "$svc"; then
    systemctl stop "$svc" && echo "stopped $svc"
  else
    echo "$svc not installed, skipping"
  fi
done

# also stop the demo listener if it is running (no-op otherwise)
if [ -n "${SUDO_USER:-}" ]; then
  sudo -u "$SUDO_USER" bash "$(dirname "$0")/attack_demo.sh" stop || true
fi

free -h | head -2
