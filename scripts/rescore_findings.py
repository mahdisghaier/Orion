"""(Re)compute the priority score of every finding from the evidence ORION holds.

New findings are scored when their hunt runs, and a finding's pattern is rescored whenever an
analyst decides on it. Use this for findings that predate scoring, or after changing the weights
in app/services/prioritization.py. Only priority_score / priority_breakdown are written.

Dry run by default.   python scripts/rescore_findings.py            (report only)
                      python scripts/rescore_findings.py --apply    (write)
"""
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.database import async_session  # noqa: E402
from app.models import HuntResult  # noqa: E402
from app.services.prioritization import rescore_findings  # noqa: E402


# [explain] Recalculate every finding's priority score (and its reasons) from the stored evidence.
# [explain] Without --apply it only reports what would change.
async def main(apply: bool) -> None:
    logging.disable(logging.CRITICAL)
    async with async_session() as db:
        findings = (await db.execute(select(HuntResult))).scalars().all()
        before = {f.id: f.priority_score for f in findings}
        await rescore_findings(db, findings)
        changed = sum(1 for f in findings if before[f.id] != f.priority_score)
        print(f"{len(findings)} finding(s) scored, {changed} changed")
        buckets = {"70-100": 0, "40-69": 0, "0-39": 0}
        for f in findings:
            buckets["70-100" if f.priority_score >= 70 else "40-69" if f.priority_score >= 40 else "0-39"] += 1
        print("distribution:", buckets)
        if apply:
            await db.commit()
            print("written")
        else:
            await db.rollback()
            print("dry run: nothing written (use --apply)")


if __name__ == "__main__":
    asyncio.run(main("--apply" in sys.argv))
