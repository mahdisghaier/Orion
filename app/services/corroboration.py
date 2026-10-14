"""Attach derived information (corroboration, history) to findings before they are serialized."""
from typing import Iterable, List

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HuntResult


async def attach_corroboration(db: AsyncSession, findings: Iterable[HuntResult]) -> List[HuntResult]:
    """Set `corroborated_by` on each finding: the OTHER findings sharing its correlation_id.

    One query for the whole batch. The attribute is not a column; the response schema reads it.
    """
    findings = list(findings)
    ids = {f.correlation_id for f in findings if f.correlation_id}
    siblings = {}
    if ids:
        rows = (await db.execute(
            select(HuntResult.id, HuntResult.siem_type, HuntResult.correlation_id)
            .where(HuntResult.correlation_id.in_(ids))
        )).all()
        for row in rows:
            siblings.setdefault(row.correlation_id, []).append({"id": row.id, "siem_type": row.siem_type})
    for f in findings:
        f.corroborated_by = [s for s in siblings.get(f.correlation_id, []) if s["id"] != f.id]
    return findings


async def attach_history(db: AsyncSession, findings: Iterable[HuntResult]) -> List[HuntResult]:
    """Set `previous_hunts` and `known_since` on each finding.

    A finding whose fingerprint was already produced by earlier hunts is not new information:
    the analyst should see that, and since when. One query for the whole batch.
    """
    findings = list(findings)
    fingerprints = {f.fingerprint for f in findings if f.fingerprint}
    stats = {}
    if fingerprints:
        rows = (await db.execute(
            select(
                HuntResult.fingerprint,
                func.count(func.distinct(HuntResult.hunt_id)),
                func.min(func.coalesce(HuntResult.first_seen, HuntResult.event_time)),
            )
            .where(HuntResult.fingerprint.in_(fingerprints))
            .group_by(HuntResult.fingerprint)
        )).all()
        stats = {fp: (hunts, since) for fp, hunts, since in rows}
    for f in findings:
        hunts, since = stats.get(f.fingerprint, (1, None))
        f.previous_hunts = max(hunts - 1, 0)          # the finding's own hunt is one of the counted
        f.known_since = since if hunts > 1 else None
    return findings


async def enrich_findings(db: AsyncSession, findings: Iterable[HuntResult]) -> List[HuntResult]:
    findings = list(findings)
    await attach_corroboration(db, findings)
    await attach_history(db, findings)
    return findings
