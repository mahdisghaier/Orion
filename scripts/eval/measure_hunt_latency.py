"""How long does a hunt take, from the request to the ranked list of findings? Measured on the lab by calling the hunt
runner of the platform (the code the API calls) for rules of the library on both SIEMs, over the last 24 hours."""
import asyncio
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import select  # noqa: E402

from app.core.database import async_session  # noqa: E402
from app.models import SIEMConnection, User  # noqa: E402
from app.services.hunt_runner import HuntRunner  # noqa: E402
from app.services.threat_intel.rules import rules_for  # noqa: E402

TECHNIQUES = ["T1046", "T1105", "T1070.003", "T1059.004"]
REPEATS = 5


async def main() -> None:
    async with async_session() as db:
        admin = (await db.execute(select(User).where(User.role == "admin").limit(1))).scalar_one()
        conns = (await db.execute(select(SIEMConnection).where(SIEMConnection.is_active.is_(True)))).scalars().all()
        client = conns[0].client_id
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
        print(f"{len(conns)} active connections, window 24 h")
        for technique in TECHNIQUES:
            rule = rules_for(technique)[0]
            times, hits = [], 0
            for _ in range(REPEATS):
                started = time.perf_counter()
                hunt = await HuntRunner(db).create_and_run(
                    created_by=admin.id, siem_targets=[c.id for c in conns], rule_yaml=rule["yaml"],
                    time_range={"from": since}, client_id=client)
                times.append(time.perf_counter() - started)
                hits = hunt.total_hits
            print(f"{technique}: median {statistics.median(times):.2f} s, min {min(times):.2f} s, max {max(times):.2f} s, {hits} findings")


asyncio.run(main())
