"""Deterministic finding priority: a 0-100 score that always comes with its reasons.

The score is computed by ORION from evidence it already holds. The LLM never assigns or changes
it (deterministic precedence): it may only EXPLAIN the ranking, using the breakdown stored with
each finding. All weights live in WEIGHTS / TACTIC_POINTS below so they can be tuned in one
place and defended in the thesis.

  corroboration   +25   another SIEM independently reported the same behaviour
  severity       0-25   the worse of: MITRE tactic tier (design doc tier table) and Wazuh rule level
  new            +15    first time this behaviour appears in any hunt
  persistence    0-10   long-lived or frequently seen activity (log2 of occurrences, +2 over 30 min)
  analyst        -30..+20  past decisions on the same behaviour: validated/escalated up, false positive down
  sensor        -10..0  weaker evidence: a Wazuh event derived from text, not from structured fields
  suppressed     -> 0   an analyst declared the pattern known benign
"""
import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Hunt, HuntResult, SigmaRule
from app.services.ecs import get_nested

WEIGHTS = {
    "corroboration": 25,
    "new": 15,
    "persistence_max": 10,
    "persistence_long_window_minutes": 30,
    "persistence_long_window_bonus": 2,
    "validated": 20,
    "false_positive_each": -10,
    "false_positive_max_decisions": 3,
    "wazuh_derived": -5,
    "wazuh_text_only": -10,
}

# MITRE tactic -> severity points. Follows the intervention tier table of the design
# (Tier 1* = credential access, lateral movement, C2, exfiltration; Tier 3 = recon, discovery).
TACTIC_POINTS = {
    "credential_access": 25, "lateral_movement": 25, "command_and_control": 25, "exfiltration": 25,
    "initial_access": 18, "execution": 18, "persistence": 18, "privilege_escalation": 18,
    "defense_evasion": 18, "collection": 18, "impact": 18,
    "reconnaissance": 8, "resource_development": 8, "discovery": 8,
}
DEFAULT_TACTIC_POINTS = 10          # no tactic known: neither alarming nor ignorable
WAZUH_LEVEL_POINTS_PER_LEVEL = 2    # Wazuh rule.level 0-15 -> capped at 25


def normalize_tactic(name: str) -> str:
    return str(name).strip().lower().replace("-", "_").replace(" ", "_")


@dataclass
class Signals:
    siem_type: str
    other_sources: Tuple[str, ...] = ()       # other SIEMs that reported the same behaviour
    tactics: Tuple[str, ...] = ()
    event_level: Optional[int] = None         # Wazuh rule.level
    previous_hunts: int = 0
    occurrence_count: int = 1
    span_minutes: float = 0.0
    validated: int = 0                        # includes escalated
    false_positive: int = 0
    derived: bool = False                     # Wazuh event derived from a text diff
    has_process: bool = True
    suppressed: bool = False


@dataclass
class Scored:
    score: int
    breakdown: List[dict] = field(default_factory=list)


def _tier(points: int) -> str:
    return {25: "Tier 1", 18: "Tier 2", 8: "Tier 3"}.get(points, "no tier")


def score(signals: Signals) -> Scored:
    parts: List[dict] = []

    def add(factor: str, points: int, detail: str) -> None:
        parts.append({"factor": factor, "points": points, "detail": detail})

    if signals.suppressed:
        return Scored(0, [{"factor": "suppressed", "points": 0,
                           "detail": "an analyst declared this pattern known benign"}])

    if signals.other_sources:
        add("corroboration", WEIGHTS["corroboration"],
            "also reported by " + ", ".join(sorted(signals.other_sources)))
    else:
        add("corroboration", 0, "single SIEM")

    # severity: the worse of tactic tier and Wazuh rule level
    tactic_pts, tactic_name = 0, None
    for tactic in signals.tactics:
        points = TACTIC_POINTS.get(normalize_tactic(tactic))
        if points is not None and points > tactic_pts:
            tactic_pts, tactic_name = points, normalize_tactic(tactic)
    level_pts = 0
    if signals.event_level is not None:
        level_pts = min(25, max(0, signals.event_level) * WAZUH_LEVEL_POINTS_PER_LEVEL)
    if tactic_name is None and signals.event_level is None:
        add("severity", DEFAULT_TACTIC_POINTS, "no MITRE tactic or rule level known")
    elif tactic_pts >= level_pts:
        add("severity", tactic_pts, f"tactic {tactic_name} ({_tier(tactic_pts)})")
    else:
        add("severity", level_pts, f"Wazuh rule level {signals.event_level}")

    if signals.previous_hunts == 0:
        add("new", WEIGHTS["new"], "first time this behaviour appears")
    else:
        add("new", 0, f"already found in {signals.previous_hunts} earlier hunt(s)")

    persistence = 0
    if signals.occurrence_count > 1:
        persistence = int(math.log2(signals.occurrence_count))
        if signals.span_minutes >= WEIGHTS["persistence_long_window_minutes"]:
            persistence += WEIGHTS["persistence_long_window_bonus"]
        persistence = min(WEIGHTS["persistence_max"], persistence)
    add("persistence", persistence,
        f"seen {signals.occurrence_count}x over {signals.span_minutes:.0f} min" if persistence else "seen once")

    if signals.validated:
        add("analyst", WEIGHTS["validated"], f"{signals.validated} earlier finding(s) of this pattern confirmed by an analyst")
    elif signals.false_positive:
        steps = min(signals.false_positive, WEIGHTS["false_positive_max_decisions"])
        add("analyst", WEIGHTS["false_positive_each"] * steps,
            f"{signals.false_positive} earlier finding(s) of this pattern marked false positive")
    else:
        add("analyst", 0, "no analyst decision on this pattern yet")

    if signals.siem_type == "wazuh" and signals.derived:
        add("sensor", WEIGHTS["wazuh_derived"], "Wazuh event derived from a text diff")
    elif signals.siem_type == "wazuh" and not signals.has_process:
        add("sensor", WEIGHTS["wazuh_text_only"], "Wazuh event matched on alert text only")
    else:
        add("sensor", 0, "structured fields")

    total = sum(p["points"] for p in parts)
    return Scored(max(0, min(100, total)), parts)


# ── persistence: computing signals from the database ─────────────────────────────

async def fingerprint_stats(db: AsyncSession, fingerprints: Iterable[str]) -> Dict[str, dict]:
    """Per fingerprint: distinct hunts, earliest sighting, and analyst decisions across all copies."""
    fingerprints = {f for f in fingerprints if f}
    if not fingerprints:
        return {}
    rows = (await db.execute(
        select(
            HuntResult.fingerprint,
            func.count(func.distinct(HuntResult.hunt_id)),
            func.min(func.coalesce(HuntResult.first_seen, HuntResult.event_time)),
            func.count(HuntResult.id).filter(HuntResult.analyst_status.in_(("validated", "escalated"))),
            func.count(HuntResult.id).filter(HuntResult.analyst_status == "false_positive"),
        )
        .where(HuntResult.fingerprint.in_(fingerprints))
        .group_by(HuntResult.fingerprint)
    )).all()
    return {fp: {"hunts": hunts, "since": since, "validated": validated, "false_positive": fps}
            for fp, hunts, since, validated, fps in rows}


async def rescore_findings(db: AsyncSession, findings: Iterable[HuntResult]) -> None:
    """Compute and store priority_score / priority_breakdown for each finding (batched queries)."""
    findings = list(findings)
    if not findings:
        return

    stats = await fingerprint_stats(db, (f.fingerprint for f in findings))

    correlation_ids = {f.correlation_id for f in findings if f.correlation_id}
    members: Dict[str, Dict[str, int]] = {}
    if correlation_ids:
        for corr, siem in (await db.execute(
            select(HuntResult.correlation_id, HuntResult.siem_type)
            .where(HuntResult.correlation_id.in_(correlation_ids))
        )).all():
            members.setdefault(corr, {}).setdefault(siem, 0)
            members[corr][siem] += 1

    rule_tactics: Dict[object, List[str]] = {}
    hunt_ids = {f.hunt_id for f in findings}
    for hunt_id, tactics in (await db.execute(
        select(Hunt.id, SigmaRule.mitre_tactics)
        .join(SigmaRule, SigmaRule.id == Hunt.rule_id, isouter=True)
        .where(Hunt.id.in_(hunt_ids))
    )).all():
        rule_tactics[hunt_id] = list(tactics or [])

    for f in findings:
        event = f.ecs_event or {}
        st = stats.get(f.fingerprint, {})
        tactics = list(rule_tactics.get(f.hunt_id, []))
        tactics += [t for t in (get_nested(event, "threat.tactic.name") or []) if t]
        span = 0.0
        if f.first_seen and f.last_seen:
            span = max(0.0, (f.last_seen - f.first_seen).total_seconds() / 60)
        other = tuple(s for s in members.get(f.correlation_id, {}) if s != f.siem_type) if f.correlation_id else ()

        result = score(Signals(
            siem_type=f.siem_type,
            other_sources=other,
            tactics=tuple(tactics),
            event_level=get_nested(event, "event.severity"),
            previous_hunts=max(st.get("hunts", 1) - 1, 0),
            occurrence_count=f.occurrence_count or 1,
            span_minutes=span,
            validated=st.get("validated", 1 if f.analyst_status in ("validated", "escalated") else 0),
            false_positive=st.get("false_positive", 1 if f.analyst_status == "false_positive" else 0),
            derived=bool(get_nested(event, "orion.derived_from")),
            has_process=bool(f.process_name),
            suppressed=f.suppression_id is not None,
        ))
        f.priority_score = result.score
        f.priority_breakdown = result.breakdown


async def rescore_fingerprint(db: AsyncSession, fingerprint: Optional[str]) -> int:
    """Recompute every finding sharing a fingerprint (an analyst decision changes them all)."""
    if not fingerprint:
        return 0
    findings = (await db.execute(select(HuntResult).where(HuntResult.fingerprint == fingerprint))).scalars().all()
    await rescore_findings(db, findings)
    return len(findings)
