#!/usr/bin/env bash
# Install the Wazuh agent (version pinned to the manager's) on this host and enrol it
# against the Dockerized manager (ports 1514/1515 published on 127.0.0.1).
# Run:  sudo bash scripts/lab/install_wazuh_agent.sh      (idempotent)
# Stop: sudo bash scripts/lab/stop_lab.sh
set -euo pipefail

MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
AGENT_NAME="${AGENT_NAME:-wsl-ubuntu}"
MANAGER_ADDR="127.0.0.1"
MIN_FREE_MB=400

[ "$(id -u)" = 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }

avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
[ "$avail_mb" -ge "$MIN_FREE_MB" ] || { echo "Only ${avail_mb} MB RAM available. Free memory first."; exit 1; }

# The agent must NOT be newer than the manager: take the version from the manager itself.
# [explain] Ask the manager which version it is: the agent must never be newer than the manager.
VER=$(docker exec "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-control info 2>/dev/null \
      | sed -n 's/^WAZUH_VERSION="v\(.*\)"/\1/p')
[ -n "$VER" ] || { echo "Cannot read the manager version from container $MANAGER_CONTAINER"; exit 1; }
echo "Manager version: $VER"

for p in 1514 1515; do
  timeout 3 bash -c "</dev/tcp/$MANAGER_ADDR/$p" 2>/dev/null \
    || { echo "Port $p on $MANAGER_ADDR is not reachable (is the manager container up and publishing it?)"; exit 1; }
done

# --- apt repo -------------------------------------------------------------------
if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
  apt-get install -y curl gpg apt-transport-https ca-certificates
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update
fi

# [explain] Find the exact package version that matches the manager. If it does not exist we stop and ask.
PKGVER=$(apt-cache madison wazuh-agent | awk -F'|' '{gsub(/ /,"",$2); print $2}' | grep -m1 "^${VER}-" || true)
if [ -z "$PKGVER" ]; then
  echo "wazuh-agent ${VER}-* is not available in the apt repo. Available versions:"
  apt-cache madison wazuh-agent | head
  echo "Nothing installed. Tell me which version to use."
  exit 1
fi

installed=$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null || true)
if [ "$installed" != "$PKGVER" ]; then
  apt-mark unhold wazuh-agent 2>/dev/null || true
  WAZUH_MANAGER="$MANAGER_ADDR" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y "wazuh-agent=$PKGVER"
fi

# Make sure the agent points at the local manager
sed -i "s|<address>.*</address>|<address>$MANAGER_ADDR</address>|" /var/ossec/etc/ossec.conf

# Enrol if the install did not (re-runs, or an earlier partial run).
# On Docker Desktop the published port 1515 can reset the TLS enrolment handshake even though
# authd works inside the container. In that case create the agent through the manager container
# and install the key locally (the key is never printed).
# [explain] No key file means this agent is not registered with the manager yet: register it now.
if [ ! -s /var/ossec/etc/client.keys ]; then
  if ! /var/ossec/bin/agent-auth -m "$MANAGER_ADDR" -A "$AGENT_NAME"; then
    echo "agent-auth failed; enrolling through the manager container instead"
    agent_id() {
      docker exec "$MANAGER_CONTAINER" /var/ossec/bin/manage_agents -l 2>/dev/null \
        | sed -n "s/.*ID: \([0-9]*\), Name: ${AGENT_NAME},.*/\1/p" | head -1
    }
    id=$(agent_id)
    if [ -z "$id" ]; then
      docker exec "$MANAGER_CONTAINER" /var/ossec/bin/manage_agents -a any -n "$AGENT_NAME" >/dev/null
      id=$(agent_id)
    fi
    [ -n "$id" ] || { echo "Could not create agent '$AGENT_NAME' on the manager"; exit 1; }
    key=$(docker exec "$MANAGER_CONTAINER" /var/ossec/bin/manage_agents -e "$id" 2>/dev/null \
          | grep -E '^[A-Za-z0-9+/=]{40,}$' | head -1)
    [ -n "$key" ] || { echo "Could not extract the key for agent $id"; exit 1; }
    echo "$key" | base64 -d > /var/ossec/etc/client.keys
    chown root:wazuh /var/ossec/etc/client.keys
    chmod 640 /var/ossec/etc/client.keys
    echo "agent '$AGENT_NAME' registered as ID $id"
  fi
fi

systemctl daemon-reload
# [explain] Start the agent now and at every boot.
systemctl enable --now wazuh-agent
apt-mark hold wazuh-agent >/dev/null

echo "Installed wazuh-agent $PKGVER, name '$AGENT_NAME', manager $MANAGER_ADDR (held)."
echo "Check with: bash scripts/lab/status.sh"
