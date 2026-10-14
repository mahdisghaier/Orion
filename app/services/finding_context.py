"""Read-only events around a finding, from the SIEM that reported it.

Shared by the analyst's "Related events" panel and by approved pivot steps of an investigation, so
both go through exactly the same guardrails: one of three fixed pivots (host, process, user), a
bounded window, a bounded size, and connector-side parameterised queries (no query text from users).
"""
from datetime import timedelta, timezone
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HuntResult, SIEMConnection
from app.services.connectors.factory import ConnectorError, get_connector
from app.services.ecs import extract_ecs_fields, get_nested

PIVOT_FIELD = {"host": "host_name", "process": "process_name", "user": "user_name"}
MAX_WINDOW_MINUTES = 120
MAX_EVENTS = 200


class ContextError(Exception):
    """A pivot that cannot be performed; carries the HTTP status the API should answer with."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


async def fetch_finding_context(db: AsyncSession, finding: HuntResult, pivot: str,
                                window: int, limit: int) -> dict:
    """Returns {pivot, entity, siem_type, connection_name, window_minutes, time_from, time_to, events: [...]}."""
    if pivot not in PIVOT_FIELD:
        raise ContextError(422, f"Unknown pivot: {pivot}")
    window = max(1, min(window, MAX_WINDOW_MINUTES))
    limit = max(1, min(limit, MAX_EVENTS))

    value = getattr(finding, PIVOT_FIELD[pivot])
    if not value:
        raise ContextError(422, f"This finding has no {pivot} to pivot on")

    connection = await db.get(SIEMConnection, finding.siem_connection_id) if finding.siem_connection_id else None
    if connection is None or not connection.is_active:
        raise ContextError(409, "The SIEM connection for this finding is no longer active")
    try:
        connector = get_connector(connection)
    except ConnectorError as e:
        raise ContextError(409, str(e))

    centre = finding.last_seen or finding.event_time
    if centre.tzinfo is None:
        centre = centre.replace(tzinfo=timezone.utc)
    start, end = centre - timedelta(minutes=window), centre + timedelta(minutes=window)
    entity = {"host": finding.host_name, "process_name": finding.process_name, "user": finding.user_name}

    try:
        raw_events = await connector.fetch_context(pivot, entity, start, end, limit)
    except NotImplementedError as e:
        raise ContextError(501, str(e))
    except Exception as e:
        raise ContextError(502, f"{connection.name}: {e}")

    events: List[dict] = []
    for raw in raw_events:
        fields = extract_ecs_fields(raw)
        events.append({
            "time": fields["event_time"], "host": fields["host_name"], "user": fields["user_name"],
            "process_name": fields["process_name"], "pid": get_nested(raw, "process.pid"),
            "command_line": fields["process_command_line"], "action": fields["action"],
            "message": get_nested(raw, "message"), "rule_id": get_nested(raw, "rule.id"),
            "severity": get_nested(raw, "event.severity"),
        })
    return {
        "pivot": pivot, "entity": entity, "siem_type": finding.siem_type, "connection_name": connection.name,
        "window_minutes": window, "time_from": start, "time_to": end, "events": events,
    }
