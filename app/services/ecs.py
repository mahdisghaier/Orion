"""ECS field extraction — pulls indexed fields from raw SIEM events."""
from datetime import datetime, timezone
from typing import Optional, Any
from dateutil import parser as date_parser


# [explain] Read a value deep inside a dictionary using a dotted path, e.g. "process.name", without crashing if a step is missing.
def get_nested(d: dict, path: str, default: Any = None) -> Any:
    keys = path.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


# [explain] Turn a time written as text into a real date. If it has no time zone, assume UTC.
def parse_event_time(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = date_parser.isoparse(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


# [explain] Pull the same handful of details out of any event (time, host, user, process, command, action, addresses)
# [explain] so the rest of ORION does not care which SIEM the event came from.
def extract_ecs_fields(raw_event: dict) -> dict:
    return {
        "event_time": parse_event_time(get_nested(raw_event, "@timestamp")) or datetime.now(timezone.utc),
        "source_ip": get_nested(raw_event, "source.ip"),
        "destination_ip": get_nested(raw_event, "destination.ip"),
        "user_name": get_nested(raw_event, "user.name"),
        "host_name": get_nested(raw_event, "host.name"),
        "process_name": get_nested(raw_event, "process.name"),
        "process_command_line": get_nested(raw_event, "process.command_line"),
        "action": get_nested(raw_event, "event.action"),
    }


# [explain] A Sigma rule can carry tags like attack.t1046 (a technique) or attack.discovery (a tactic). Split them into the two lists.
def extract_mitre_from_tags(tags: Optional[list]) -> tuple:
    if not tags:
        return ([], [])
    tactics = []
    techniques = []
    for tag in tags:
        if not tag.startswith("attack."):
            continue
        rest = tag.removeprefix("attack.")
        if rest.startswith("t") and len(rest) >= 5:
            technique_id = "T" + rest[1:]
            techniques.append(technique_id)
        elif not rest.startswith("t"):
            tactics.append(rest)
    return (tactics, techniques)
