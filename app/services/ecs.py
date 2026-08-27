"""ECS field extraction — pulls indexed fields from raw SIEM events."""
from datetime import datetime, timezone
from typing import Optional, Any
from dateutil import parser as date_parser


def get_nested(d: dict, path: str, default: Any = None) -> Any:
    keys = path.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


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
