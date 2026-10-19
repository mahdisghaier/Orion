"""Group repeated events of a hunt into one finding each.

Process telemetry is sampled (Metricbeat every 30 s), so one long-lived process becomes
dozens of identical events. An analyst should triage "this process, seen 61 times between
A and B", not 61 rows. Events are grouped per SIEM connection by a fingerprint of what the
event MEANS (host, process, command line, user, action, network endpoints, rule). PID and
timestamps are left out on purpose: they change between samples of the same behaviour.
"""
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from app.services.ecs import get_nested


@dataclass
class EventGroup:
    fingerprint: str
    event: dict            # representative: the most recent event of the group
    fields: dict           # extract_ecs_fields() of the representative
    count: int
    first_seen: datetime
    last_seen: datetime


_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX_ID = re.compile(r"\b[0-9a-f]{8,}\b")
_MIXED_TOKEN = re.compile(r"\b(?=[0-9a-z]*\d)[0-9a-z]{4,}\b")   # random names such as run3 or 3fa9
_NUMBER = re.compile(r"\d+")


def normalise_command_line(text) -> str:
    """The command line with its variable parts masked, so repeats of one behaviour share a fingerprint.

    Port numbers, counts, durations, process identifiers, random temporary names (any word of four or more characters
    that contains a digit) and hexadecimal identifiers
    change from one run of the same command to the next (``nc -l 127.0.0.1 38831`` and ``nc -l 127.0.0.1 21106``
    are the same behaviour). Addresses are kept, because the destination of a command matters. The finding keeps the
    real command line of its newest event; only the fingerprint uses the masked form.
    """
    if not text:
        return ""
    lowered = str(text).lower()
    addresses = _IPV4.findall(lowered)
    masked = _NUMBER.sub("#", _MIXED_TOKEN.sub("#", _HEX_ID.sub("#", _IPV4.sub("@", lowered))))
    return masked + "|" + ",".join(addresses)


def fingerprint(siem_type: str, event: dict, fields: dict) -> str:
    parts = [
        siem_type,
        fields.get("host_name"),
        fields.get("process_name"),
        get_nested(event, "process.executable"),
        normalise_command_line(fields.get("process_command_line")),
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


def for_client(fp: str, client_id) -> str:
    """A fingerprint inside one client. The same behaviour of two clients must not share a suppression or a history."""
    if client_id is None:
        return fp
    return hashlib.sha1(f"{fp}\x1f{client_id}".encode("utf-8")).hexdigest()[:16]


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
