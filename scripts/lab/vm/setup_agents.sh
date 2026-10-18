#!/usr/bin/env bash
# Install the two data sources of the lab inside the Ubuntu VM:
#   - Wazuh agent 4.8.0 (alerts, file integrity monitoring, listening ports)
#   - Auditbeat 8.15.0 (every process start and outgoing connection, through the Linux audit system)
# Run inside the VM:  sudo bash setup_agents.sh [SERVER_ADDRESS]
# SERVER_ADDRESS is where the Elastic and Wazuh servers can be reached from the VM (default 10.0.2.2, the NAT gateway).
# Idempotent: running it again repairs a partial installation.
set -uo pipefail
HOST="${1:-10.0.2.2}"
WATCH_DIR=/home/soc/orion-eval-fim
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl ca-certificates net-tools netcat-openbsd >/dev/null 2>&1   # netstat feeds Wazuh's listening-port check

# Repositories: the keys are kept in their text form (the binary conversion fails silently on this release).
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /usr/share/keyrings/wazuh.asc
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch -o /usr/share/keyrings/elastic.asc
echo "deb [signed-by=/usr/share/keyrings/wazuh.asc] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
echo "deb [signed-by=/usr/share/keyrings/elastic.asc] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -qq >/dev/null 2>&1

# Wazuh agent: it must not be newer than the manager (4.8.0).
apt-mark unhold wazuh-agent >/dev/null 2>&1
WAZUH_MANAGER="$HOST" WAZUH_AGENT_NAME="orion-lab" apt-get install -y -qq wazuh-agent=4.8.0-1 2>&1 | tail -1
apt-mark hold wazuh-agent >/dev/null
mkdir -p "$WATCH_DIR" && chown soc:soc "$WATCH_DIR" 2>/dev/null || true
grep -q 'orion-eval-fim' /var/ossec/etc/ossec.conf || sed -i '0,/<syscheck>/s//<syscheck>\n    <directories realtime="yes">\/home\/soc\/orion-eval-fim<\/directories>/' /var/ossec/etc/ossec.conf
systemctl daemon-reload; systemctl enable wazuh-agent >/dev/null 2>&1; systemctl restart wazuh-agent
echo "wazuh-agent: $(systemctl is-active wazuh-agent)"

# Auditbeat. If the download from Elastic fails (it did on this network), copy the .deb to /tmp/auditbeat.deb and run again.
apt-mark unhold auditbeat >/dev/null 2>&1
if ! dpkg -s auditbeat >/dev/null 2>&1; then
  if [ -s /tmp/auditbeat.deb ]; then dpkg -i /tmp/auditbeat.deb | tail -1; else apt-get install -y -qq auditbeat=8.15.0 2>&1 | tail -1; fi
fi
apt-mark hold auditbeat >/dev/null
cat > /etc/auditbeat/auditbeat.yml <<EOF
auditbeat.modules:
  - module: auditd
    audit_rules: |
      -a always,exit -F arch=b64 -S execve,execveat -k exec
      -a always,exit -F arch=b64 -S connect -F success=1 -k net
      -a always,exit -F arch=b64 -S connect -F exit=-115 -k net
      -w $WATCH_DIR -p wa -k fim

setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0
setup.ilm.enabled: true

output.elasticsearch:
  hosts: ["$HOST:9200"]

processors:
  - add_host_metadata: ~
  # the audit module stores the arguments as a list; the detection rules read the joined command line
  - script:
      lang: javascript
      source: |
        function process(event) {
          var args = event.Get("process.args");
          if (args && args.length) { event.Put("process.command_line", args.join(" ")); }
        }

logging.level: warning
EOF
chmod 600 /etc/auditbeat/auditbeat.yml
auditbeat test config -c /etc/auditbeat/auditbeat.yml 2>&1 | tail -1
auditbeat setup --index-management 2>&1 | tail -1
curl -s -X PUT "http://$HOST:9200/_ilm/policy/auditbeat" -H 'Content-Type: application/json' \
  -d '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_primary_shard_size":"1gb","max_age":"1d"}}},"delete":{"min_age":"3d","actions":{"delete":{}}}}}}' >/dev/null
mkdir -p /etc/systemd/system/auditbeat.service.d
printf '[Service]\nMemoryMax=300M\n' > /etc/systemd/system/auditbeat.service.d/limits.conf
systemctl daemon-reload; systemctl enable auditbeat >/dev/null 2>&1; systemctl restart auditbeat
echo "auditbeat: $(systemctl is-active auditbeat)"
