"""What the planner is allowed to know: SIEM capabilities, relevant findings, steps already taken.

Everything that comes from logs is clipped and later placed inside an <untrusted_data> block in the
prompt: command lines and host names are attacker-controlled text and must be treated as data only.
"""
import re
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HuntResult, Investigation, SIEMConnection, SIEMProfile
from app.services.corroboration import enrich_findings
from app.services.data_profile import SIEM_FIELD_MAPS

MAX_FINDINGS = 8


def clip(value, limit: int = 200):
    """One line, bounded, and unable to close the untrusted-data fence."""
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value)).strip().replace("</untrusted_data>", "")
    return text[:limit]


def sigma_field_availability(siem_type: str, profile: dict) -> Dict[str, object]:
    """Sigma field -> percent of recent events that carry it; None when never measured; 0 = blind spot."""
    out: Dict[str, object] = {}
    measured = (profile or {}).get("fields", {})
    for sigma_field, target in SIEM_FIELD_MAPS.get(siem_type, {}).items():
        targets = list(target) if isinstance(target, (list, tuple)) else [target]
        pcts = [measured[t]["pct"] for t in targets if t in measured]
        out[sigma_field] = min(pcts) if pcts and len(pcts) == len(targets) else None
    return out


def finding_view(f: HuntResult) -> dict:
    return {
        "id": str(f.id),
        "siem": f.siem_type,
        "host": clip(f.host_name, 80),
        "process": clip(f.process_name, 80),
        "command_line": clip(f.process_command_line),
        "user": clip(f.user_name, 80),
        "action": clip(f.action, 80),
        "priority": f.priority_score,
        "why": [f"{b['points']:+d} {b['factor']}: {clip(b['detail'], 120)}"
                for b in (f.priority_breakdown or []) if b.get("points")],
        "occurrences": f.occurrence_count,
        "also_reported_by": [c["siem_type"] for c in getattr(f, "corroborated_by", [])],
        "earlier_hunts": getattr(f, "previous_hunts", 0),
        "analyst_status": f.analyst_status,
    }


def step_outcome(step) -> str:
    result = step.result or {}
    if step.status == "rejected":
        return "rejected by the analyst" + (f": {clip(step.decision_comment, 120)}" if step.decision_comment else "")
    if step.status == "failed":
        return f"failed: {clip(step.error, 160)}"
    if step.kind == "rule" and result:
        return f"{result.get('total_hits', 0)} finding(s)" + (f"; notes: {clip(result.get('notes'), 160)}" if result.get("notes") else "")
    if step.kind == "pivot" and result:
        return f"{result.get('count', 0)} related event(s)"
    return step.status


async def build_context(db: AsyncSession, inv: Investigation) -> dict:
    connections = (await db.execute(
        select(SIEMConnection).where(SIEMConnection.id.in_(inv.siem_targets), SIEMConnection.is_active.is_(True))
    )).scalars().all()
    profiles = {
        row.siem_connection_id: row.profile
        for row in (await db.execute(
            select(SIEMProfile).where(SIEMProfile.siem_connection_id.in_([c.id for c in connections]))
        )).scalars().all()
    }

    siems: List[dict] = []
    for c in connections:
        profile = profiles.get(c.id)
        siems.append({
            "connection": c.name,
            "siem_type": c.type,
            "profiled": profile is not None,
            "recent_events": (profile or {}).get("recent_docs"),
            "latest_event": (profile or {}).get("latest"),
            "common_event_kinds": [t["value"][:60] for t in (profile or {}).get("top", [])[:8]],
            "sigma_field_population_pct": sigma_field_availability(c.type, profile or {}),
        })

    # findings relevant to this investigation: its source finding and what its rule steps found;
    # before anything ran, the current top findings
    hunt_ids = [s.hunt_id for s in inv.steps if s.hunt_id]
    cond = []
    if hunt_ids:
        cond.append(HuntResult.hunt_id.in_(hunt_ids))
    if inv.source_finding_id:
        cond.append(HuntResult.id == inv.source_finding_id)
    query = select(HuntResult).where(HuntResult.suppression_id.is_(None))
    if cond:
        from sqlalchemy import or_
        query = query.where(or_(*cond))
    findings = (await db.execute(
        query.order_by(HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc()).limit(60)
    )).scalars().all()
    seen, unique = set(), []
    for f in findings:                      # one per behaviour
        key = f.fingerprint or str(f.id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = await enrich_findings(db, unique[:MAX_FINDINGS])

    return {
        "siems": siems,
        "findings": [finding_view(f) for f in findings],
        "steps_so_far": [
            {"seq": s.seq, "kind": s.kind, "title": clip(s.title, 120), "status": s.status, "outcome": step_outcome(s)}
            for s in inv.steps
        ],
    }
