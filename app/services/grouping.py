"""Group repeated events of a hunt into one finding each.

Process telemetry is sampled (Metricbeat every 30 s), so one long-lived process becomes
dozens of identical events. An analyst should triage "this process, seen 61 times between
A and B", not 61 rows. Events are grouped per SIEM connection by a fingerprint of what the
event MEANS (host, process, command line, user, action, network endpoints, rule). PID and
timestamps are left out on purpose: they change between samples of the same behaviour.
"""
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from app.services.ecs import get_nested


# [explain] One finding made of many identical events: the newest one as the example, how many there were, first and last time.
@dataclass
class EventGroup:
    fingerprint: str
    event: dict            # representative: the most recent event of the group
    fields: dict           # extract_ecs_fields() of the representative
    count: int
    first_seen: datetime
    last_seen: datetime


# [explain] A name tag for a BEHAVIOUR: host + process + command + user + action + addresses.
# [explain] The process number and the time are left out on purpose: they change every time but the behaviour is the same.
def fingerprint(siem_type: str, event: dict, fields: dict) -> str:
    parts = [
        siem_type,
        fields.get("host_name"),
        fields.get("process_name"),
        get_nested(event, "process.executable"),
        fields.get("process_command_line"),
        fields.get("user_name"),
        fields.get("action"),
        fields.get("source_ip"),
        fields.get("destination_ip"),
        get_nested(event, "destination.port"),
        get_nested(event, "rule.id"),
        # alerts with nothing else to tell them apart (rootcheck, PAM, ...) differ by message
        get_nested(event, "message") if not fields.get("process_name") else None,
    ]
    raw = "\x1f".join("" if p is None else str(p).lower() for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


# [explain] Put events with the same name tag in the same pile, and count them. 61 identical photos become "seen 61 times".
def group_events(siem_type: str, items: Iterable[Tuple[dict, dict]]) -> List[EventGroup]:
    """items: (event, extract_ecs_fields(event)) pairs, any order. Returns groups, newest first."""
    groups: Dict[str, EventGroup] = {}
    for event, fields in items:
        key = fingerprint(siem_type, event, fields)
        when = fields["event_time"]
        group = groups.get(key)
        if group is None:
            groups[key] = EventGroup(key, event, fields, 1, when, when)
            continue
        group.count += 1
        group.first_seen = min(group.first_seen, when)
        if when >= group.last_seen:
            group.last_seen = when
            group.event, group.fields = event, fields
    return sorted(groups.values(), key=lambda g: g.last_seen, reverse=True)
