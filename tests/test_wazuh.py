"""Wazuh support: Sigma -> Lucene, runnable-or-not, alert -> ECS mapping, connector request shape.

Fixtures mirror the shape of real alerts captured in the lab (rule 533 netstat change,
rule 5403 sudo) with names and values replaced by generic ones.

Run:  python -m unittest discover -s tests -t . -v
"""
import json
import unittest

import httpx

from app.services.connectors.wazuh import WazuhConnector
from app.services.connectors.wazuh_ecs import (
    parse_netstat_lines,
    query_process_names,
    wazuh_to_ecs_events,
)
from app.services.ecs import extract_ecs_fields
from app.services.sigma_engine import convert_sigma_rule, unmapped_fields

NC_RULE = """title: netcat
logsource: {product: linux, category: process_creation}
detection:
  selection:
    Image|endswith: ['/nc', '/ncat', '/netcat', '/nc.openbsd']
  condition: selection
tags: [attack.t1046]
"""

HEADER = "ossec: output: 'netstat listening ports':"
BASE_PORTS = [
    "tcp6       0      0 :::1514                 :::*                    LISTEN      -                   ",
    "udp 127.0.0.53:53 0.0.0.0:* 87/systemd-resolved",
    "tcp 127.0.0.1:5432 0.0.0.0:* 421/postgres",
]
NC_LINE = "tcp 127.0.0.1:4444 0.0.0.0:* 13663/nc"


def netstat_alert(current, previous, alert_id="1.1"):
    return {
        "@timestamp": "2026-01-01T10:00:00.000Z",
        "timestamp": "2026-01-01T10:00:00.000+0000",
        "id": alert_id,
        "agent": {"id": "001", "name": "lab-host", "ip": "127.0.0.1"},
        "rule": {"id": "533", "level": 7, "description": "Listened ports status (netstat) changed",
                 "groups": ["ossec"]},
        "decoder": {"name": "ossec"},
        "full_log": "\n".join([HEADER, *current]),
        "previous_log": "\n".join([HEADER, *previous]),
        "location": "netstat listening ports",
    }


SUDO_ALERT = {
    "@timestamp": "2026-01-01T10:05:00.000Z",
    "id": "2.2",
    "agent": {"id": "001", "name": "Lab-Host"},
    "rule": {"id": "5403", "level": 4, "description": "First time user executed sudo.",
             "groups": ["syslog", "sudo"],
             "mitre": {"id": ["T1548.003"], "technique": ["Sudo and Sudo Caching"],
                       "tactic": ["Privilege Escalation", "Defense Evasion"]}},
    "decoder": {"name": "sudo"},
    "data": {"srcuser": "analyst", "dstuser": "root", "pwd": "/home/analyst",
             "command": "/usr/bin/bash scripts/run.sh"},
    "full_log": "sudo: analyst : USER=root ; COMMAND=/usr/bin/bash scripts/run.sh",
}


SYSCHECK_ALERT = {
    "@timestamp": "2026-01-01T10:10:00.000Z",
    "id": "3.3",
    "agent": {"id": "001", "name": "Lab-Host"},
    "rule": {"id": "554", "level": 5, "description": "File added to the system.", "groups": ["ossec", "syscheck"]},
    "decoder": {"name": "syscheck_new_entry"},
    "syscheck": {"path": "/home/analyst/watched/report.txt", "mode": "realtime", "event": "added",
                 "size_after": "12", "sha256_after": "ab" * 32},
    "full_log": "File '/home/analyst/watched/report.txt' added",
}


class SyscheckAlerts(unittest.TestCase):
    def test_file_alert_becomes_a_file_event(self):
        (e,) = wazuh_to_ecs_events(SYSCHECK_ALERT)
        self.assertEqual(e["file"]["path"], "/home/analyst/watched/report.txt")
        self.assertEqual(e["file"]["hash"]["sha256"], "ab" * 32)
        self.assertEqual(e["event"]["action"], "file-added")
        self.assertEqual(e["event"]["category"], ["file"])
        self.assertIn("/home/analyst/watched/report.txt", e["message"])        # tells two file alerts apart

    def test_target_filename_rule_converts_for_wazuh_and_elastic(self):
        rule = """title: file
logsource: {product: linux, category: file_event}
detection:
  selection:
    TargetFilename|contains: 'watched/report'
  condition: selection
"""
        result = convert_sigma_rule(rule)
        self.assertIn("syscheck.path:*watched\\/report*", result["lucene"])
        self.assertIn("file.path", result["eql"])
        self.assertEqual(unmapped_fields(rule, "wazuh"), [])


class SigmaToLucene(unittest.TestCase):
    def test_image_becomes_basename_tokens(self):
        # pySigma's default "*\/nc" matches nothing on the analysed full_log text field
        self.assertEqual(
            convert_sigma_rule(NC_RULE)["lucene"],
            "full_log:(nc OR ncat OR netcat OR nc.openbsd)",
        )

    def test_keyword_fields_keep_wildcards(self):
        rule = NC_RULE.replace("Image|endswith: ['/nc', '/ncat', '/netcat', '/nc.openbsd']",
                               "User: analyst\n    CommandLine|contains: run.sh")
        lucene = convert_sigma_rule(rule)["lucene"]
        self.assertIn("data.srcuser:analyst", lucene)
        self.assertIn("data.command:*run.sh*", lucene)

    def test_unmapped_field_is_not_runnable(self):
        rule = NC_RULE.replace("selection:\n", "selection:\n    ParentImage|endswith: /bash\n")
        self.assertEqual(unmapped_fields(rule, "wazuh"), ["ParentImage"])
        self.assertEqual(unmapped_fields(rule, "elastic"), [])      # ECS has process.parent.executable
        self.assertEqual(unmapped_fields(NC_RULE, "wazuh"), [])
        self.assertEqual(unmapped_fields(rule, "unknown-siem"), [])


class NetstatDiff(unittest.TestCase):
    def test_parses_both_line_shapes(self):
        parsed = parse_netstat_lines("\n".join([HEADER, *BASE_PORTS, NC_LINE]))
        self.assertEqual([p["port"] for p in parsed], [1514, 53, 5432, 4444])
        nc = parsed[-1]
        self.assertEqual((nc["name"], nc["pid"], nc["address"], nc["proto"]), ("nc", 13663, "127.0.0.1", "tcp"))
        self.assertIsNone(parsed[0]["name"])                         # raw netstat line has no process

    def test_new_listener_becomes_an_event_with_process_fields(self):
        alert = netstat_alert(BASE_PORTS + [NC_LINE], BASE_PORTS)
        events = wazuh_to_ecs_events(alert)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["event"]["action"], "listening-port-opened")
        self.assertEqual((e["process"]["name"], e["process"]["pid"]), ("nc", 13663))
        self.assertEqual((e["destination"]["ip"], e["destination"]["port"]), ("127.0.0.1", 4444))
        self.assertEqual(e["host"]["name"], "lab-host")
        self.assertNotIn("previous_log", e["wazuh"])

    def test_closed_listener(self):
        alert = netstat_alert(BASE_PORTS, BASE_PORTS + [NC_LINE])
        events = wazuh_to_ecs_events(alert)
        self.assertEqual([e["event"]["action"] for e in events], ["listening-port-closed"])

    def test_name_filter_drops_unrelated_changes(self):
        # the alert text contains "nc" in its table, but what changed is postgres
        other = "tcp 127.0.0.1:5433 0.0.0.0:* 999/postgres"
        alert = netstat_alert(BASE_PORTS + [NC_LINE, other], BASE_PORTS + [NC_LINE])
        self.assertEqual(len(wazuh_to_ecs_events(alert)), 1)
        self.assertEqual(wazuh_to_ecs_events(alert, name_filter={"nc"}), [])

    def test_query_process_names(self):
        self.assertEqual(query_process_names("full_log:(nc OR ncat)"), {"nc", "ncat"})
        self.assertEqual(query_process_names("full_log:nc"), {"nc"})
        self.assertEqual(query_process_names("(full_log:(NC OR Ncat)) AND data.srcuser:x"), {"nc", "ncat"})
        self.assertIsNone(query_process_names("data.srcuser:analyst"))


class GenericAlerts(unittest.TestCase):
    def test_sudo_alert(self):
        (e,) = wazuh_to_ecs_events(SUDO_ALERT, host_aliases={"Lab-Host": "workstation-1"})
        self.assertEqual(e["host"]["name"], "workstation-1")
        self.assertEqual(e["user"], {"name": "analyst", "target": {"name": "root"}})
        self.assertEqual(e["process"]["name"], "bash")
        self.assertEqual(e["process"]["executable"], "/usr/bin/bash")
        self.assertEqual(e["process"]["command_line"], "/usr/bin/bash scripts/run.sh")
        self.assertEqual(e["threat"]["technique"]["id"], ["T1548.003"])

    def test_host_name_is_lowercased_without_alias(self):
        (e,) = wazuh_to_ecs_events(SUDO_ALERT)
        self.assertEqual(e["host"]["name"], "lab-host")

    def test_extract_ecs_fields_reads_derived_events(self):
        (e,) = wazuh_to_ecs_events(netstat_alert(BASE_PORTS + [NC_LINE], BASE_PORTS))
        fields = extract_ecs_fields(e)
        self.assertEqual(fields["process_name"], "nc")
        self.assertEqual(fields["destination_ip"], "127.0.0.1")
        self.assertEqual(fields["host_name"], "lab-host")
        self.assertEqual(fields["action"], "listening-port-opened")
        self.assertEqual(fields["event_time"].year, 2026)


class ConnectorRequest(unittest.IsolatedAsyncioTestCase):
    def make(self, handler):
        connector = WazuhConnector("https://wazuh.example:9200/", "user", "pw", verify_ssl=False)
        connector._client = lambda timeout: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), auth=connector._auth, timeout=timeout)
        return connector

    async def test_query_shape_and_mapping(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["auth"] = request.headers.get("authorization", "")
            seen["body"] = json.loads(request.content)
            alert = netstat_alert(BASE_PORTS + [NC_LINE], BASE_PORTS)
            return httpx.Response(200, json={"hits": {"hits": [{"_source": alert}]}})

        connector = self.make(handler)
        events = await connector.run_query(
            "full_log:(nc OR ncat)", max_results=5000, time_range={"from": "now-7d"})

        self.assertEqual(seen["url"], "https://wazuh.example:9200/wazuh-alerts-*/_search")
        self.assertTrue(seen["auth"].startswith("Basic "))
        body = seen["body"]
        self.assertEqual(body["size"], 1000)                         # capped
        self.assertEqual(body["query"]["bool"]["must"][0]["query_string"]["query"], "full_log:(nc OR ncat)")
        self.assertEqual(body["query"]["bool"]["filter"], [{"range": {"@timestamp": {"gte": "now-7d"}}}])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["process"]["name"], "nc")

    async def test_http_error_is_wrapped_without_credentials(self):
        connector = self.make(lambda r: httpx.Response(401, text="unauthorized"))
        with self.assertRaises(Exception) as ctx:
            await connector.run_query("full_log:nc")
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn("pw", str(ctx.exception))

    async def test_connection_health(self):
        ok = self.make(lambda r: httpx.Response(200, json={"status": "green"}))
        red = self.make(lambda r: httpx.Response(200, json={"status": "red"}))
        denied = self.make(lambda r: httpx.Response(401))
        self.assertTrue(await ok.test_connection())
        self.assertFalse(await red.test_connection())
        self.assertFalse(await denied.test_connection())


if __name__ == "__main__":
    unittest.main()
