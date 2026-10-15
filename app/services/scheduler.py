"""Runs due jobs in the background of the API process.

A loop wakes every minute, finds enabled jobs whose next_run_at has passed, and runs them one at a time. State lives in the
database (next_run_at, job_runs), so a restart loses nothing except a run that was in progress, which is marked as interrupted.

Assumption: ONE API process. With several workers every one of them would run the loop; a lock in the database would be needed.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Callable, List, Optional

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session
from app.models import JobRun, ScheduledJob
from app.services.threat_intel.runner import Deps, run_job

log = logging.getLogger("orion.scheduler")
TICK_SECONDS = 60
_running_jobs: set = set()
_lock = asyncio.Lock()


async def due_jobs(db: AsyncSession, now: datetime) -> List[ScheduledJob]:
    return list((await db.execute(
        select(ScheduledJob).where(ScheduledJob.enabled.is_(True), or_(ScheduledJob.next_run_at.is_(None), ScheduledJob.next_run_at <= now))
        .order_by(ScheduledJob.next_run_at.nulls_first())
    )).scalars().all())


async def run_one(job_id, trigger: str, session_factory: Callable = async_session, deps: Optional[Deps] = None) -> Optional[JobRun]:
    """Run a job in its own session. Returns None if that job is already running."""
    if job_id in _running_jobs:
        return None
    _running_jobs.add(job_id)
    try:
        async with _lock:                                  # one run at a time: they share the SIEMs and the machine's memory
            async with session_factory() as db:
                job = await db.get(ScheduledJob, job_id)
                if job is None:
                    return None
                return await run_job(db, job, trigger, deps)
    finally:
        _running_jobs.discard(job_id)


def is_running(job_id) -> bool:
    return job_id in _running_jobs


async def mark_interrupted(session_factory: Callable = async_session) -> int:
    """A run still 'running' when the server starts was cut off by a restart."""
    async with session_factory() as db:
        result = await db.execute(
            update(JobRun).where(JobRun.status == "running")
            .values(status="error", error="interrupted by a server restart", finished_at=datetime.now(timezone.utc))
        )
        await db.commit()
        return result.rowcount


async def scheduler_loop(stop: asyncio.Event, session_factory: Callable = async_session, tick: float = TICK_SECONDS) -> None:
    await mark_interrupted(session_factory)
    while not stop.is_set():
        try:
            async with session_factory() as db:
                ids = [j.id for j in await due_jobs(db, datetime.now(timezone.utc))]
            for job_id in ids:
                await run_one(job_id, "schedule", session_factory)
        except Exception:
            log.exception("scheduler tick failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=tick)
        except asyncio.TimeoutError:
            pass
