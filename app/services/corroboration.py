"""Attach "also seen by" information to findings before they are serialized."""
from typing import Iterable, List

from sqlalchemy import select
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
