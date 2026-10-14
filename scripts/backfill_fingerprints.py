"""Give findings created before grouping a fingerprint, so they collapse like newer ones.

The fingerprint is derived from content already stored in the row (host, process, command
line, user, action, endpoints, rule), exactly as services/grouping.py computes it for new
findings. Nothing else is changed: evidence (ecs_event / raw_event) is untouched, occurrence_count
stays 1 and first_seen / last_seen are set to the finding's own event_time.

Dry run by default.   python scripts/backfill_fingerprints.py            (report only)
                      python scripts/backfill_fingerprints.py --apply    (write)
Idempotent: rows that already have a fingerprint are skipped.
"""
import asyncio
import logging
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.database import async_session  # noqa: E402
from app.models import HuntResult  # noqa: E402
from app.services.grouping import fingerprint  # noqa: E402


async def main(apply: bool) -> None:
    logging.disable(logging.CRITICAL)
    async with async_session() as db:
        rows = (await db.execute(select(HuntResult).where(HuntResult.fingerprint.is_(None)))).scalars().all()
        counts = Counter()
        for row in rows:
            fields = {
                "host_name": row.host_name, "process_name": row.process_name,
                "process_command_line": row.process_command_line, "user_name": row.user_name,
                "action": row.action, "source_ip": row.source_ip, "destination_ip": row.destination_ip,
            }
            fp = fingerprint(row.siem_type, row.ecs_event or {}, fields)
            counts[fp] += 1
            if apply:
                row.fingerprint = fp
                row.first_seen = row.first_seen or row.event_time
                row.last_seen = row.last_seen or row.event_time
        print(f"{len(rows)} finding(s) without a fingerprint -> {len(counts)} distinct behaviour(s)")
        if apply:
            await db.commit()
            print("written")
        else:
            print("dry run: nothing written (use --apply)")


if __name__ == "__main__":
    asyncio.run(main("--apply" in sys.argv))
