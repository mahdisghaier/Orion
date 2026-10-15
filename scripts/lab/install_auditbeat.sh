#!/usr/bin/env bash
# Install and configure Auditbeat 8.15.0 -> Elastic, giving ORION what Metricbeat's 30 s polling cannot:
#   auditd module  : every execve (short-lived processes included), with full arguments as process.command_line
#   socket dataset : network connections (source/destination address and port, owning process)
# Run:  sudo bash scripts/lab/install_auditbeat.sh      (idempotent)
# Stop: sudo systemctl stop auditbeat
set -euo pipefail

VER="8.15.0"                       # must match the cluster version
ES="${ES_URL:-http://localhost:9200}"
MIN_FREE_MB=600

[ "$(id -u)" = 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }

avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
if [ "$avail_mb" -lt "$MIN_FREE_MB" ]; then
  echo "Only ${avail_mb} MB RAM available (< ${MIN_FREE_MB}). Free memory first."
  exit 1
fi

cluster_ver=$(curl -fsS "$ES" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["version"]["number"])') \
  || { echo "Elasticsearch not reachable at $ES"; exit 1; }
[ "$cluster_ver" = "$VER" ] || { echo "Cluster is $cluster_ver, script pins $VER. Aborting."; exit 1; }

# The kernel must be able to audit system calls. Auditbeat takes the audit netlink socket itself,
# so a running auditd would fight it for that socket.
if [ -r /proc/config.gz ] && ! zcat /proc/config.gz | grep -q '^CONFIG_AUDITSYSCALL=y'; then
  echo "This kernel has no syscall auditing (CONFIG_AUDITSYSCALL). Auditbeat cannot see process starts here."
  exit 1
fi
if systemctl is-active --quiet auditd 2>/dev/null; then
  echo "auditd is running and would compete with Auditbeat. Stop it first: sudo systemctl stop auditd"
  exit 1
fi

# --- apt repo + package (same repo as Metricbeat) ---------------------------
if [ ! -f /etc/apt/sources.list.d/elastic-8.x.list ]; then
  apt-get install -y curl gpg apt-transport-https ca-certificates
  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list
  apt-get update
fi

installed=$(dpkg-query -W -f='${Version}' auditbeat 2>/dev/null || true)
if [ "$installed" != "$VER" ]; then
  apt-mark unhold auditbeat 2>/dev/null || true
  apt-get install -y "auditbeat=$VER"
fi
apt-mark hold auditbeat >/dev/null

# --- configuration ------------------------------------------------------------
[ -f /etc/auditbeat/auditbeat.yml.orig ] || cp /etc/auditbeat/auditbeat.yml /etc/auditbeat/auditbeat.yml.orig

cat > /etc/auditbeat/auditbeat.yml <<'EOF'
auditbeat.modules:
  - module: auditd
    audit_rules: |
      -a always,exit -F arch=b64 -S execve,execveat -k exec
      -a always,exit -F arch=b32 -S execve,execveat -k exec
  - module: system
    datasets:
      - socket
    socket.include_localhost: false

setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0     # single node: avoids a permanently yellow cluster
setup.ilm.enabled: true

output.elasticsearch:
  hosts: ["localhost:9200"]

processors:
  - add_host_metadata: ~
  # the auditd module stores the arguments as a list; ORION's rules read the joined command line
  - script:
      lang: javascript
      source: |
        function process(event) {
          var args = event.Get("process.args");
          if (args && args.length) { event.Put("process.command_line", args.join(" ")); }
        }

logging.level: warning
EOF
chown root:root /etc/auditbeat/auditbeat.yml
chmod 600 /etc/auditbeat/auditbeat.yml
auditbeat test config -c /etc/auditbeat/auditbeat.yml

# --- template + ILM before the first event, so field types are right ----------
auditbeat setup --index-management
curl -fsS -X PUT "$ES/_ilm/policy/auditbeat" -H 'Content-Type: application/json' -d '{
  "policy": {"phases": {
    "hot":    {"actions": {"rollover": {"max_primary_shard_size": "1gb", "max_age": "1d"}}},
    "delete": {"min_age": "3d", "actions": {"delete": {}}}
  }}}' >/dev/null
echo "ILM policy 'auditbeat': rollover 1d/1gb, delete after 3d"

mkdir -p /etc/systemd/system/auditbeat.service.d
printf '[Service]\nMemoryMax=300M\n' > /etc/systemd/system/auditbeat.service.d/limits.conf
systemctl daemon-reload
systemctl enable --now auditbeat

echo "Generating one process start and one connection so there is something to find..."
/bin/true; (exec 3<>/dev/tcp/127.0.0.1/9200 && exec 3>&-) 2>/dev/null || true
echo "Waiting up to 90s for the first documents..."
for _ in $(seq 1 18); do
  n=$(curl -s "$ES/auditbeat-*/_count" | python3 -I -c 'import sys,json; print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0)
  [ "${n:-0}" -gt 0 ] && break
  sleep 5
done
echo "auditbeat-* docs: ${n:-0}"
echo "Next: add an Elastic connection in ORION with index pattern auditbeat-* (see docs), then check: bash scripts/lab/status.sh"
