#!/usr/bin/env bash
# Let the Wazuh agent watch ONE folder for file changes in real time (file-integrity monitoring),
# so the evaluation can measure what Wazuh sees that process telemetry cannot.
# Only ~/orion-eval-fim is watched. Idempotent; undo with:  sudo bash scripts/lab/enable_fim_demo.sh --undo
# Run:  sudo bash scripts/lab/enable_fim_demo.sh
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }
[ -n "${SUDO_USER:-}" ] || { echo "Run it through sudo from your own account (SUDO_USER is empty)"; exit 1; }

CONF=/var/ossec/etc/ossec.conf
DIR="$(getent passwd "$SUDO_USER" | cut -d: -f6)/orion-eval-fim"
LINE="<directories realtime=\"yes\" check_all=\"yes\">$DIR</directories>"
[ -f "$CONF" ] || { echo "$CONF not found: is the Wazuh agent installed?"; exit 1; }

# [explain] --undo: stop watching the folder again (removes the line we added).
if [ "${1:-}" = "--undo" ]; then
  python3 - "$CONF" "$LINE" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2]
text = open(path).read()
open(path, "w").write("\n".join(l for l in text.split("\n") if line not in l))
PY
  systemctl restart wazuh-agent
  echo "folder no longer watched"
  exit 0
fi

# [explain] Create the scratch folder that will be watched, owned by you (not by root).
mkdir -p "$DIR"
chown "$SUDO_USER":"$SUDO_USER" "$DIR"

if grep -qF "$LINE" "$CONF"; then
  echo "already watching $DIR"
else
  [ -f "$CONF.orig-before-fim" ] || cp "$CONF" "$CONF.orig-before-fim"
  python3 - "$CONF" "$LINE" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2]
text = open(path).read()
marker = "<syscheck>"
if marker not in text:
    raise SystemExit("no <syscheck> block found in ossec.conf")
i = text.index(marker) + len(marker)
open(path, "w").write(text[:i] + "\n    " + line + text[i:])
PY
  echo "added: $LINE"
fi

# [explain] Restart the agent so it reads its new configuration.
systemctl restart wazuh-agent
sleep 3
systemctl is-active wazuh-agent
echo "Watching $DIR in real time. Check with: bash scripts/lab/status.sh"
