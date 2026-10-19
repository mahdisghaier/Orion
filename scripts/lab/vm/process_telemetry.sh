#!/usr/bin/env bash
# Run on the lab VM as root, after setup_agents.sh. One sensor, two readers.
# Auditbeat records every process start, outgoing connection and change in the watched folder through the Linux audit
# system and writes each event as one JSON line in /var/log/orion-sensor/. Filebeat ships those lines to Elastic, and the
# Wazuh agent reads the same file, so that Wazuh sees the same activity as Elastic. A rule on the Wazuh manager
# (local_rules.xml, see wazuh_rules.xml) turns the process-start lines into alerts. The .deb of Filebeat is copied to
# /tmp/filebeat.deb beforehand when the VM cannot download it.
set -euo pipefail
HOST="${HOST:-10.0.2.2}"
WATCH_DIR=/home/soc/orion-eval-fim
LOGDIR=/var/log/orion-sensor
mkdir -p "$LOGDIR"

systemctl disable --now auditd >/dev/null 2>&1 || true
systemctl stop filebeat auditbeat 2>/dev/null || true
cat > /etc/auditbeat/auditbeat.yml <<EOF
auditbeat.modules:
  - module: auditd
    audit_rules: |
      -a always,exit -F arch=b64 -S execve,execveat -k exec
      -a always,exit -F arch=b64 -S connect -F success=1 -k net
      -a always,exit -F arch=b64 -S connect -F exit=-115 -k net
      -w $WATCH_DIR -p wa -k fim

processors:
  - add_host_metadata: ~
  # Wazuh already maps data.file as a plain string, so the file description of a process start (which Elastic does
  # not use for these events) is dropped; otherwise the alerts would be refused by the Wazuh indexer
  - drop_fields:
      when:
        equals:
          event.action: executed
      fields: [file]
      ignore_missing: true
  # the audit module stores the arguments as a list; the detection rules read the joined command line
  - script:
      lang: javascript
      source: |
        function process(event) {
          var args = event.Get("process.args");
          if (args && args.length) { event.Put("process.command_line", args.join(" ")); }
        }

output.file:
  path: "$LOGDIR"
  filename: events
  rotate_every_kb: 20000
  number_of_files: 3

logging.level: warning
EOF
chmod 600 /etc/auditbeat/auditbeat.yml

if ! dpkg -s filebeat >/dev/null 2>&1; then
  if [ -s /tmp/filebeat.deb ]; then dpkg -i /tmp/filebeat.deb | tail -1; else apt-get install -y -qq filebeat=8.15.0 2>&1 | tail -1; fi
fi
cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
  - type: filestream
    id: auditbeat-events
    paths: ["$LOGDIR/events*.ndjson"]
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true

setup.template.enabled: false
setup.ilm.enabled: false

output.elasticsearch:
  hosts: ["$HOST:9200"]
  index: "auditbeat-8.15.0"

logging.level: warning
EOF
chmod 600 /etc/filebeat/filebeat.yml

# the Wazuh agent reads the same file
python3 - <<'PY'
import re
p = "/var/ossec/etc/ossec.conf"
s = open(p).read()
# remove an audit.log reader added earlier, and any empty or broken localfile block
s = re.sub(r"[ \t]*<localfile>\s*<log_format>audit</log_format>.*?</localfile>\n", "", s, flags=re.S)
s = re.sub(r"[ \t]*<localfile>\s*<log_format>json</log_format>\s*<location>/var/log/(auditbeat|orion-sensor)/[^<]*</location>\s*</localfile>\n", "", s)
s = re.sub(r"[ \t]*<localfile>\s*(?=<localfile>)", "", s)
block = "  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/orion-sensor/events*.ndjson</location>\n  </localfile>\n"
if "orion-sensor" not in s:
    s = s.replace("</ossec_config>", block + "</ossec_config>", 1)
open(p, "w").write(s)
PY
rm -f /etc/audit/rules.d/orion.rules
systemctl daemon-reload
systemctl enable auditbeat filebeat >/dev/null 2>&1
systemctl restart auditbeat; sleep 2; systemctl restart filebeat; systemctl restart wazuh-agent
sleep 4
echo "auditbeat: $(systemctl is-active auditbeat)  filebeat: $(systemctl is-active filebeat)  wazuh-agent: $(systemctl is-active wazuh-agent)"
