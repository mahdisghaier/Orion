#!/usr/bin/env bash
# Is the Wazuh vulnerability detector producing data? No sudo needed (uses docker).
#   bash scripts/lab/vuln_status.sh          show config, last feed result, indexed record count
#   bash scripts/lab/vuln_status.sh retry    restart the manager so it downloads the CVE feed again now
# The feed is downloaded from cti.wazuh.com; a "partial file" error means the transfer was cut (slow or unstable
# network). The manager retries by itself every feed-update-interval (60m by default).
#   export WAZUH_INDEXER_PASS='...'   to also count records in the indexer
set -uo pipefail

MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
WZ="${WAZUH_INDEXER_URL:-https://localhost:9201}"

case "${1:-status}" in
status)
  echo "== config =="
  docker exec "$MANAGER_CONTAINER" sh -c "grep -A4 '<vulnerability-detection>' /var/ossec/etc/ossec.conf"
  echo "== last feed and inventory messages =="
  docker exec "$MANAGER_CONTAINER" sh -c "grep -i -E 'content-updater|vulnerab' /var/ossec/logs/ossec.log | tail -6"
  echo "== indexed vulnerability records =="
  if [ -n "${WAZUH_INDEXER_PASS:-}" ]; then
    curl -sk --max-time 20 -u "${WAZUH_INDEXER_USER:-admin}:$WAZUH_INDEXER_PASS" "$WZ/wazuh-states-vulnerabilities-*/_count"; echo
  else
    echo "  (set WAZUH_INDEXER_PASS to count them)"
  fi
  ;;
retry)
  docker restart "$MANAGER_CONTAINER" >/dev/null && echo "manager restarted; check again in a few minutes with: bash $0"
  ;;
*) echo "usage: $0 [status|retry]"; exit 2 ;;
esac
