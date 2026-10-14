"""Attach derived information (corroboration, history) to findings before they are serialized."""
from typing import Iterable, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import HuntResult
from app.services.prioritization import fingerprint_stats


# [explain] For each finding, look up the OTHER findings that share its correlation id ("also seen by Wazuh").
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


# [explain] For each finding, count how many earlier hunts already produced the same behaviour ("not new").
async def attach_history(db: AsyncSession, findings: Iterable[HuntResult]) -> List[HuntResult]:
    """Set `previous_hunts` and `known_since` on each finding.

    A finding whose fingerprint was already produced by earlier hunts is not new information:
    the analyst should see that, and since when. One query for the whole batch.
    """
    findings = list(findings)
    stats = await fingerprint_stats(db, (f.fingerprint for f in findings))
    for f in findings:
        st = stats.get(f.fingerprint, {"hunts": 1, "since": None})
        f.previous_hunts = max(st["hunts"] - 1, 0)          # the finding's own hunt is one of the counted
        f.known_since = st["since"] if st["hunts"] > 1 else None
    return findings


# [explain] One call that adds both extras before a finding is sent to the screen.
async def enrich_findings(db: AsyncSession, findings: Iterable[HuntResult]) -> List[HuntResult]:
    findings = list(findings)
    await attach_corroboration(db, findings)
    await attach_history(db, findings)
    return findings
