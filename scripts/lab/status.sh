#!/usr/bin/env bash
# Lab status and evidence collection. No sudo needed.
#   bash scripts/lab/status.sh            summary
#   bash scripts/lab/status.sh proc       raw Metricbeat doc(s) for process.name == "nc" (EQL)
#   bash scripts/lab/status.sh alert      newest Wazuh alerts for the agent + raw JSON of those mentioning 4444
#
# The Wazuh indexer password is NOT stored in this repo:
#   export WAZUH_INDEXER_PASS='...'     (lab default; user "admin")
set -uo pipefail

ES="${ES_URL:-http://localhost:9200}"
WZ="${WAZUH_INDEXER_URL:-https://localhost:9201}"
WZ_USER="${WAZUH_INDEXER_USER:-admin}"
WZ_PASS="${WAZUH_INDEXER_PASS:-}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
AGENT="${AGENT_NAME:-wsl-ubuntu}"

wz() { curl -sk --max-time 20 -u "$WZ_USER:$WZ_PASS" "$@"; }
pyj() { python3 -I -c "$1"; }

need_pass() {
  [ -n "$WZ_PASS" ] || { echo "  (set WAZUH_INDEXER_PASS to query the Wazuh indexer)"; return 1; }
}

# [explain] Three views: the summary, the raw Elastic event for the netcat test, or the raw Wazuh alerts.
case "${1:-summary}" in
summary)
  echo "== Elastic =="
  curl -s --max-time 10 "$ES/_cluster/health" | pyj 'import sys,json; d=json.load(sys.stdin); print("  status:", d["status"], "| nodes:", d["number_of_nodes"])' 2>/dev/null || echo "  unreachable"
  n=$(curl -s --max-time 10 "$ES/metricbeat-*/_count" | pyj 'import sys,json; print(json.load(sys.stdin).get("count","n/a"))' 2>/dev/null || echo n/a)
  echo "  metricbeat-* docs: $n"
  curl -s --max-time 10 "$ES/metricbeat-*/_mapping/field/process.executable" | pyj '
import sys,json
d=json.load(sys.stdin); seen=set()
for idx,v in d.items():
    for f in v["mappings"].values():
        seen.add(f["mapping"]["executable"]["type"])
print("  process.executable mapping:", ", ".join(sorted(seen)) or "no index yet")' 2>/dev/null || echo "  process.executable mapping: n/a"

  echo "== Wazuh manager =="
  docker exec "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-control info 2>/dev/null | grep WAZUH_VERSION | sed 's/^/  /'
  docker exec "$MANAGER_CONTAINER" /var/ossec/bin/agent_control -l 2>/dev/null | sed 's/^/  /' || echo "  manager container not reachable"

  echo "== Wazuh indexer =="
  docker ps --format '  {{.Names}}: {{.Status}}' | grep wazuh.indexer
  if need_pass; then
    wz "$WZ/wazuh-alerts-*/_count" -H 'Content-Type: application/json' \
       -d "{\"query\":{\"term\":{\"agent.name\":\"$AGENT\"}}}" \
       | pyj 'import sys,json; print("  wazuh-alerts-* docs for agent '"$AGENT"':", json.load(sys.stdin).get("count","error"))' 2>/dev/null \
       || echo "  indexer unreachable or auth failed"
  fi

  echo "== Memory =="
  free -h
  ;;

proc)
  # The same EQL ORION generates. Shows the full raw documents.
  curl -s --max-time 20 "$ES/metricbeat-*/_eql/search" -H 'Content-Type: application/json' \
    -d '{"query":"any where process.name == \"nc\"","size":3}' | pyj '
import sys,json
d=json.load(sys.stdin)
ev=d.get("hits",{}).get("events",[])
print("events:", len(ev), "(error: %s)" % d.get("error") if "error" in d else "")
for e in ev: print(json.dumps(e["_source"], indent=2))'
  ;;

alert)
  need_pass || exit 1
  wz "$WZ/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
     -d "{\"size\":50,\"sort\":[{\"timestamp\":\"desc\"}],\"query\":{\"term\":{\"agent.name\":\"$AGENT\"}}}" | pyj '
import sys,json
d=json.load(sys.stdin)
hits=[h["_source"] for h in d.get("hits",{}).get("hits",[])]
print("newest alerts for agent (up to 50 scanned):")
for s in hits[:10]:
    print("  ", s.get("timestamp"), "rule", s.get("rule",{}).get("id"), "L%s" % s.get("rule",{}).get("level"), s.get("rule",{}).get("description"))
match=[s for s in hits if "4444" in json.dumps(s)]
print("\nalerts mentioning 4444:", len(match))
for s in match[:2]: print(json.dumps(s, indent=2))'
  ;;

*) echo "usage: $0 [summary|proc|alert]"; exit 2 ;;
esac
