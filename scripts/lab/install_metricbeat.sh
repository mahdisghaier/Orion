#!/usr/bin/env bash
# Install and configure Metricbeat 8.15.0 (system/process metricset, 30s) -> Elastic.
# Run:  sudo bash scripts/lab/install_metricbeat.sh      (idempotent)
# Stop: sudo bash scripts/lab/stop_lab.sh
set -euo pipefail

VER="8.15.0"                       # must match the cluster version
ES="${ES_URL:-http://localhost:9200}"
MIN_FREE_MB=800

[ "$(id -u)" = 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }

avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
if [ "$avail_mb" -lt "$MIN_FREE_MB" ]; then
  echo "Only ${avail_mb} MB RAM available (< ${MIN_FREE_MB}). Free memory first (stop containers you do not need)."
  exit 1
fi

cluster_ver=$(curl -fsS "$ES" | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["version"]["number"])') \
  || { echo "Elasticsearch not reachable at $ES"; exit 1; }
[ "$cluster_ver" = "$VER" ] || { echo "Cluster is $cluster_ver, script pins $VER. Aborting."; exit 1; }

# --- apt repo + package -----------------------------------------------------
if [ ! -f /etc/apt/sources.list.d/elastic-8.x.list ]; then
  apt-get install -y curl gpg apt-transport-https ca-certificates
  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list
  apt-get update
fi

installed=$(dpkg-query -W -f='${Version}' metricbeat 2>/dev/null || true)
if [ "$installed" != "$VER" ]; then
  apt-mark unhold metricbeat 2>/dev/null || true
  apt-get install -y "metricbeat=$VER"
fi
apt-mark hold metricbeat >/dev/null

# --- refuse to reuse a data stream whose mapping is already wrong ------------
code=$(curl -s -o /dev/null -w '%{http_code}' "$ES/_data_stream/metricbeat-$VER")
if [ "$code" = "200" ]; then
  t=$(curl -s "$ES/metricbeat-$VER/_mapping/field/process.executable" | python3 -I -c '
import sys,json
d=json.load(sys.stdin)
for idx in d.values():
    for f in idx["mappings"].values():
        print(f["mapping"]["executable"]["type"]); raise SystemExit
print("none")')
  if [ "$t" != "keyword" ] && [ "$t" != "none" ]; then
    echo "Existing data stream metricbeat-$VER maps process.executable as '$t'."
    echo "Nothing was deleted. If it holds no data you need: curl -X DELETE $ES/_data_stream/metricbeat-$VER"
    exit 1
  fi
fi

# --- configuration ------------------------------------------------------------
[ -f /etc/metricbeat/metricbeat.yml.orig ] || cp /etc/metricbeat/metricbeat.yml /etc/metricbeat/metricbeat.yml.orig

cat > /etc/metricbeat/metricbeat.yml <<'EOF'
metricbeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false

setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0     # single node: avoids a permanently yellow cluster
setup.ilm.enabled: true

output.elasticsearch:
  hosts: ["localhost:9200"]

processors:
  - add_host_metadata: ~

logging.level: warning
EOF

metricbeat modules enable system >/dev/null 2>&1 || true
cat > /etc/metricbeat/modules.d/system.yml <<'EOF'
- module: system
  period: 30s
  metricsets:
    - process
  processes: ['.*']
  process.cgroups.enabled: false
EOF
chown root:root /etc/metricbeat/metricbeat.yml /etc/metricbeat/modules.d/system.yml
chmod 600 /etc/metricbeat/metricbeat.yml
chmod 644 /etc/metricbeat/modules.d/system.yml

metricbeat test config -c /etc/metricbeat/metricbeat.yml

# --- index template + ILM: MUST happen before the first event is shipped -----
# Without the template, process.executable would be dynamically mapped as text and EQL breaks.
metricbeat setup --index-management

# ILM: roll over daily, delete after 3 days (saves disk)
curl -fsS -X PUT "$ES/_ilm/policy/metricbeat" -H 'Content-Type: application/json' -d '{
  "policy": {"phases": {
    "hot":    {"actions": {"rollover": {"max_primary_shard_size": "1gb", "max_age": "1d"}}},
    "delete": {"min_age": "3d", "actions": {"delete": {}}}
  }}}' >/dev/null
echo "ILM policy 'metricbeat': rollover 1d/1gb, delete after 3d"

# Prove the mapping before any data exists
curl -fsS -X POST "$ES/_index_template/_simulate_index/metricbeat-$VER" | python3 -I -c '
import sys,json
m=json.load(sys.stdin)["template"]["mappings"]["properties"]
t=m["process"]["properties"]["executable"]["type"]
print("process.executable mapping type (from template):", t)
sys.exit(0 if t=="keyword" else 1)' \
  || { echo "process.executable is not keyword. Not starting Metricbeat."; exit 1; }

# --- cap memory, start --------------------------------------------------------
mkdir -p /etc/systemd/system/metricbeat.service.d
printf '[Service]\nMemoryMax=300M\n' > /etc/systemd/system/metricbeat.service.d/limits.conf
systemctl daemon-reload
systemctl enable --now metricbeat

echo "Waiting up to 90s for the first documents..."
for _ in $(seq 1 18); do
  n=$(curl -s "$ES/metricbeat-*/_count" | python3 -I -c 'import sys,json; print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0)
  [ "${n:-0}" -gt 0 ] && break
  sleep 5
done
echo "metricbeat-* docs: ${n:-0}"
echo "Done. Check with: bash scripts/lab/status.sh"
