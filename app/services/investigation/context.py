"""What the planner is allowed to know: SIEM capabilities, relevant findings, steps already taken.

Everything that comes from logs is clipped and later placed inside an <untrusted_data> block in the
prompt: command lines and host names are attacker-controlled text and must be treated as data only.
"""
import re
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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


_STOPWORDS = {
    "this", "that", "with", "from", "have", "which", "there", "their", "might", "could", "would", "should",
    "were", "been", "into", "about", "after", "before", "other", "some", "host", "found", "since", "when",
}
MIN_SIMILARITY = 0.12


def _tokens(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9_]{4,}", (text or "").lower()) if w not in _STOPWORDS}


def rank_similar(my_text: str, candidates: List[tuple], limit: int = 2) -> List[str]:
    """Ids of the candidates (id, text) most similar to my_text by word overlap (Jaccard), best first.

    Deliberately simple and explainable: no embeddings, so a result can always be justified by the shared words.
    """
    mine = _tokens(my_text)
    scored = []
    for cid, text in candidates:
        theirs = _tokens(text)
        union = mine | theirs
        score = len(mine & theirs) / len(union) if union else 0.0
        if score >= MIN_SIMILARITY:
            scored.append((score, cid))
    return [cid for _, cid in sorted(scored, key=lambda x: x[0], reverse=True)[:limit]]


async def similar_past_investigations(db: AsyncSession, inv: Investigation, limit: int = 2) -> List[dict]:
    """Concluded investigations (analyst-closed, with a verdict) about a similar hypothesis: the hunt library.

    Only investigations a human concluded are offered, so unreviewed AI output is never fed back to the model.
    """
    rows = (await db.execute(
        select(Investigation).options(selectinload(Investigation.steps))
        .where(Investigation.status == "concluded", Investigation.id != inv.id)
        .order_by(Investigation.concluded_at.desc()).limit(50)
    )).scalars().all()
    by_id = {str(r.id): r for r in rows}
    best = rank_similar(f"{inv.title} {inv.hypothesis}", [(str(r.id), f"{r.title} {r.hypothesis}") for r in rows], limit)
    out = []
    for rid in best:
        past = by_id[rid]
        executed = [s for s in past.steps if s.status == "executed"]
        rule = next((s for s in executed if s.kind == "rule"), None)
        out.append({
            "title": clip(past.title, 120),
            "hypothesis": clip(past.hypothesis, 300),
            "verdict": past.verdict,
            "conclusion": clip(past.conclusion, 400),
            "steps_that_ran": [clip(s.title, 100) for s in executed[:4]],
            "rule_that_ran": clip(rule.payload.get("sigma_rule"), 700) if rule else None,
        })
    return out


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
        "past_investigations": await similar_past_investigations(db, inv),
        "steps_so_far": [
            {"seq": s.seq, "kind": s.kind, "title": clip(s.title, 120), "status": s.status, "outcome": step_outcome(s)}
            for s in inv.steps
        ],
    }
