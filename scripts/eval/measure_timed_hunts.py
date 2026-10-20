"""Machine time of the three hunts of the timed comparison with SOC analysts, run on all stored data like the New hunt page.

    python scripts/eval/measure_timed_hunts.py
"""
import asyncio
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sqlalchemy import select  # noqa: E402

from app.core.database import async_session  # noqa: E402
from app.models import SIEMConnection, User  # noqa: E402
from app.services.hunt_runner import HuntRunner  # noqa: E402

HUNTS = [("1 download with curl or wget", "1_download_curl.yml"),
         ("2 shell history cleared", "2_history_cleared.yml"),
         ("3 netcat listener", "3_netcat_listener.yml")]
REPEATS = 5


async def main() -> None:
    async with async_session() as db:
        admin = (await db.execute(select(User).where(User.role == "admin").limit(1))).scalar_one()
        conns = (await db.execute(select(SIEMConnection).where(SIEMConnection.is_active.is_(True)))).scalars().all()
        for title, name in HUNTS:
            rule = (ROOT / "docs" / "evaluation" / "timing" / name).read_text()
            times, hunt = [], None
            for _ in range(REPEATS):
                started = time.perf_counter()
                hunt = await HuntRunner(db).create_and_run(created_by=admin.id, siem_targets=[c.id for c in conns],
                                                           rule_yaml=rule, time_range=None, client_id=conns[0].client_id)
                times.append(time.perf_counter() - started)
            print(f"{title}: median {statistics.median(times):.2f} s (min {min(times):.2f}, max {max(times):.2f}), "
                  f"{hunt.total_hits} ranked behaviours on {len(conns)} SIEMs")


asyncio.run(main())
