"""Wazuh alert -> ECS-shaped events.

Wazuh indexes ALERTS, not raw telemetry, and its fields are not ECS. This module
turns one Wazuh alert into one or more ECS-shaped event dicts so the rest of
ORION (extract_ecs_fields, findings, UI) never sees Wazuh field names.

The mapping is derived from real alerts collected in the lab:

  generic (every alert)   agent.name -> host.name, rule.* -> rule.* / event.*,
                          decoder.name -> event.provider, full_log -> event.original,
                          rule.mitre.* -> threat.*
  sudo / PAM (5403, ...)  data.srcuser -> user.name, data.dstuser -> user.target.name,
                          data.command -> process.command_line (+ name / executable),
                          data.pwd -> process.working_directory
  syscheck (550/553/554)  syscheck.path -> file.path, syscheck.event -> event.action ("file-modified")
  netstat (rule 533)      the alert carries the WHOLE listening-port table in full_log
                          and the previous table in previous_log. The new/closed
                          listeners are the lines that differ; each becomes its own
                          event with process.name / process.pid / destination.*.

No process fields exist on a Wazuh alert itself, so process.* is only ever derived.
"""
import re
from typing import Iterable, List, Optional

# "tcp 127.0.0.1:4444 0.0.0.0:* 13663/nc"   (lines rewritten by Wazuh's sed)
_NETSTAT_SED = re.compile(
    r"^(?P<proto>tcp6?|udp6?)\s+(?P<local>\S+)\s+\S+\s+(?:(?P<pid>\d+)/(?P<name>\S+))?\s*$"
)
# "tcp6       0      0 :::1514      :::*      LISTEN      -"   (lines the sed did not match)
_NETSTAT_RAW = re.compile(
    r"^(?P<proto>tcp6?|udp6?)\s+\d+\s+\d+\s+(?P<local>\S+)\s+\S+\s+(?:LISTEN\s+)?-\s*$"
)
_FULL_LOG_TERMS = re.compile(r"full_log:\(?([^()]+?)\)?(?:\s+AND\s|$|\))")

NETSTAT_RULE_ID = "533"


def _get(d: dict, path: str, default=None):
    cur = d
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur if cur is not None else default


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").split("/")[-1]


def _base_event(source: dict, host_aliases: Optional[dict]) -> dict:
    agent = _get(source, "agent.name")
    host = (host_aliases or {}).get(agent) or (agent.lower() if agent else None)
    ts = source.get("@timestamp") or source.get("timestamp")

    event = {
        "@timestamp": ts,
        "host": {"name": host},
        "message": _get(source, "rule.description"),
        "event": {
            "kind": "alert",
            "provider": _get(source, "decoder.name"),
            "severity": _get(source, "rule.level"),
            "original": source.get("full_log"),
            "dataset": "wazuh.alerts",
        },
        "rule": {"id": _get(source, "rule.id"), "name": _get(source, "rule.description")},
        "tags": list(_get(source, "rule.groups", []) or []),
        "agent": {"name": agent, "id": _get(source, "agent.id"), "type": "wazuh"},
    }

    mitre_ids = _get(source, "rule.mitre.id")
    if mitre_ids:
        event["threat"] = {
            "technique": {"id": list(mitre_ids), "name": list(_get(source, "rule.mitre.technique", []) or [])},
            "tactic": {"name": list(_get(source, "rule.mitre.tactic", []) or [])},
        }

    # Keep the original alert, minus the big duplicated "previous" blobs.
    event["wazuh"] = {k: v for k, v in source.items() if k not in ("previous_log", "previous_output")}
    return event


def _apply_data_fields(event: dict, source: dict) -> None:
    """Fields from decoded log data (sudo, PAM, sshd, ...). Only what is present is mapped."""
    data = source.get("data")
    if not isinstance(data, dict):
        return

    user = {}
    if data.get("srcuser"):
        user["name"] = data["srcuser"]
    if data.get("dstuser"):
        user["target"] = {"name": data["dstuser"]}
    if user:
        event["user"] = user

    if data.get("srcip"):
        event.setdefault("source", {})["ip"] = data["srcip"]
    if data.get("srcport"):
        event.setdefault("source", {})["port"] = data["srcport"]
    if data.get("dstip"):
        event.setdefault("destination", {})["ip"] = data["dstip"]
    if data.get("dstport"):
        event.setdefault("destination", {})["port"] = data["dstport"]

    command = data.get("command")
    if command:
        first = command.split()[0] if command.split() else ""
        process = {"command_line": command, "name": _basename(first) if first else None}
        if first.startswith("/"):
            process["executable"] = first
        if data.get("pwd"):
            process["working_directory"] = data["pwd"]
        event["process"] = process
        event["event"]["action"] = "command-executed"
    else:
        event["event"]["action"] = _get(source, "rule.description")


def _apply_syscheck(event: dict, source: dict) -> bool:
    """File-integrity alerts (syscheck): which file changed and how. True when the alert is one."""
    sc = source.get("syscheck")
    if not isinstance(sc, dict) or not sc.get("path"):
        return False
    action = f"file-{sc.get('event', 'changed')}"
    file_info = {"path": sc["path"]}
    if sc.get("size_after") not in (None, ""):
        file_info["size"] = sc["size_after"]
    if sc.get("sha256_after"):
        file_info["hash"] = {"sha256": sc["sha256_after"]}
    event["file"] = file_info
    event["event"]["action"] = action
    event["event"]["category"] = ["file"]
    event["event"]["dataset"] = "wazuh.syscheck"
    # the path is what tells two file alerts apart (their rule description is identical)
    event["message"] = f"{_get(source, 'rule.description')}: {sc['path']}"
    return True


def parse_netstat_lines(text: Optional[str]) -> List[dict]:
    """Parse the listening-port table of a rule 533 alert into listener dicts."""
    listeners = []
    for line in (text or "").splitlines()[1:]:          # first line is the header
        line = line.rstrip()
        m = _NETSTAT_SED.match(line) or _NETSTAT_RAW.match(line)
        if not m:
            continue
        local = m.group("local")
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        listeners.append({
            "line": line,
            "proto": m.group("proto"),
            "address": addr or None,
            "port": int(port),
            "pid": int(m.group("pid")) if m.groupdict().get("pid") else None,
            "name": m.groupdict().get("name"),
        })
    return listeners


def _netstat_events(source: dict, base: dict, name_filter: Optional[set]) -> List[dict]:
    current = parse_netstat_lines(source.get("full_log"))
    previous = parse_netstat_lines(source.get("previous_log"))
    cur_lines = {x["line"] for x in current}
    prev_lines = {x["line"] for x in previous}

    changes = [(x, "listening-port-opened") for x in current if x["line"] not in prev_lines]
    changes += [(x, "listening-port-closed") for x in previous if x["line"] not in cur_lines]

    events = []
    for listener, action in changes:
        if name_filter and (listener["name"] or "").lower() not in name_filter:
            continue
        ev = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
        ev["event"] = {**base["event"], "action": action, "category": ["network"], "dataset": "wazuh.netstat"}
        ev["network"] = {"transport": listener["proto"].rstrip("6")}
        ev["destination"] = {"ip": listener["address"], "port": listener["port"]}
        if listener["name"]:
            ev["process"] = {"name": listener["name"], "pid": listener["pid"]}
        ev["orion"] = {"derived_from": "wazuh_rule_533_netstat_diff", "alert_id": source.get("id")}
        events.append(ev)
    return events


def query_process_names(query: str) -> Optional[set]:
    """Process-name terms of the full_log clause in a Wazuh Lucene query, lowercased.

    The Wazuh pipeline turns Sigma's Image into "full_log:(nc OR ncat)". A rule 533 alert
    matches that whenever the listener table merely CONTAINS nc, even if the change in
    that alert was an unrelated port. These terms let us keep only the changed listeners
    the rule asked for. Returns None when the query has no full_log clause.
    """
    m = _FULL_LOG_TERMS.search(query or "")
    if not m:
        return None
    terms = {t.strip().lower() for t in re.split(r"\s+OR\s+", m.group(1)) if t.strip()}
    return terms or None


def wazuh_to_ecs_events(source: dict, host_aliases: Optional[dict] = None,
                        name_filter: Optional[Iterable[str]] = None) -> List[dict]:
    """One Wazuh alert -> list of ECS-shaped events (usually exactly one)."""
    base = _base_event(source, host_aliases)
    if str(_get(source, "rule.id")) == NETSTAT_RULE_ID:
        return _netstat_events(source, base, set(name_filter) if name_filter else None)
    if _apply_syscheck(base, source):
        return [base]
    _apply_data_fields(base, source)
    return [base]
