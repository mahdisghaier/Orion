#!/usr/bin/env bash
# Installs the process-start rule on the Wazuh manager of the lab (Docker container) and restarts the analysis engine.
set -euo pipefail
C="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
FILE=/var/ossec/etc/rules/local_rules.xml
if ! docker exec "$C" grep -q 'id="100200"' "$FILE"; then
  docker exec -i "$C" sh -c "cat >> $FILE" < "$(dirname "$0")/vm/wazuh_rules.xml"
fi
docker exec "$C" /var/ossec/bin/wazuh-control restart >/dev/null
echo "rule 100200 installed"
