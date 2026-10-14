#!/bin/bash
# Synthetic process events (tag: synthetic). Re-runnable.
curl -s -X DELETE localhost:9200/orion-process-demo > /dev/null
curl -s -X PUT localhost:9200/orion-process-demo -H 'Content-Type: application/json' -d '{"mappings":{"properties":{"@timestamp":{"type":"date"},"tags":{"type":"keyword"},"event":{"properties":{"category":{"type":"keyword"},"action":{"type":"keyword"}}},"host":{"properties":{"name":{"type":"keyword"}}},"user":{"properties":{"name":{"type":"keyword"}}},"process":{"properties":{"name":{"type":"keyword"},"executable":{"type":"keyword"},"command_line":{"type":"keyword"},"pid":{"type":"long"},"parent":{"properties":{"pid":{"type":"long"},"executable":{"type":"keyword"}}}}}}}}'
echo
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
curl -s -X POST 'localhost:9200/_bulk?refresh=true' -H 'Content-Type: application/x-ndjson' --data-binary @- > /dev/null << EOF
{"index":{"_index":"orion-process-demo"}}
{"@timestamp":"$NOW","tags":["synthetic"],"event":{"category":"process","action":"exec"},"host":{"name":"ubuntu-target"},"user":{"name":"vboxuser"},"process":{"name":"nc","executable":"/usr/bin/nc","command_line":"nc -l -p 4444","pid":4242,"parent":{"pid":1200,"executable":"/usr/bin/bash"}}}
{"index":{"_index":"orion-process-demo"}}
{"@timestamp":"$NOW","tags":["synthetic"],"event":{"category":"process","action":"exec"},"host":{"name":"ubuntu-target"},"user":{"name":"vboxuser"},"process":{"name":"ncat","executable":"/usr/bin/ncat","command_line":"ncat -lvp 9001","pid":4300,"parent":{"pid":1200,"executable":"/usr/bin/bash"}}}
{"index":{"_index":"orion-process-demo"}}
{"@timestamp":"$NOW","tags":["synthetic"],"event":{"category":"process","action":"exec"},"host":{"name":"ubuntu-target"},"user":{"name":"root"},"process":{"name":"bash","executable":"/usr/bin/bash","command_line":"bash","pid":1200,"parent":{"pid":1,"executable":"/usr/sbin/sshd"}}}
{"index":{"_index":"orion-process-demo"}}
{"@timestamp":"$NOW","tags":["synthetic"],"event":{"category":"process","action":"exec"},"host":{"name":"ubuntu-target"},"user":{"name":"vboxuser"},"process":{"name":"python3","executable":"/usr/bin/python3","command_line":"python3 app.py","pid":4400,"parent":{"pid":1200,"executable":"/usr/bin/bash"}}}
EOF
curl -s localhost:9200/orion-process-demo/_count
echo
