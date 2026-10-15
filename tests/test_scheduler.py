"""Job settings validation and the background scheduler's behaviour.

Run:  python -m unittest discover -s tests -t . -v
"""
import asyncio
import unittest
import uuid
from types import SimpleNamespace as NS

from pydantic import ValidationError

import app.services.scheduler as scheduler
from app.schemas import JobConfig, JobCreate, JobUpdate


class JobSettings(unittest.TestCase):
    def test_defaults_are_sane(self):
        job = JobCreate()
        self.assertEqual((job.kind, job.interval_hours, job.enabled), ("threat_intel", 24, True))
        self.assertEqual((job.config.campaigns, job.config.platform), (8, "Linux"))

    def test_out_of_range_and_unknown_settings_are_refused(self):
        for bad in ({"interval_hours": 0}, {"interval_hours": 400}, {"kind": "shell_command"}, {"name": ""},
                    {"config": {"campaigns": 0}}, {"config": {"platform": "Plan9"}}, {"config": {"run_this": "rm -rf /"}}):
            with self.assertRaises(ValidationError, msg=str(bad)):
                JobCreate(**bad)
        with self.assertRaises(ValidationError):
            JobUpdate(interval_hours=-1)

    def test_a_partial_update_keeps_unset_fields_unset(self):
        self.assertEqual(JobUpdate(enabled=False).model_dump(exclude_unset=True), {"enabled": False})
        self.assertEqual(JobConfig(custom_iocs={"ip": ["1.2.3.4"]}).custom_iocs, {"ip": ["1.2.3.4"]})


class SchedulerBehaviour(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.originals = (scheduler.run_job, scheduler.due_jobs, scheduler.mark_interrupted)
        scheduler._running_jobs.clear()

    def tearDown(self):
        scheduler.run_job, scheduler.due_jobs, scheduler.mark_interrupted = self.originals
        scheduler._running_jobs.clear()

    @staticmethod
    def factory(job):
        class Session:
            async def __aenter__(self):
                return NS(get=lambda model, key: asyncio.sleep(0, result=job))

            async def __aexit__(self, *a):
                return False
        return lambda: Session()

    async def test_a_job_cannot_run_twice_at_once(self):
        job = NS(id=uuid.uuid4())
        gate, started = asyncio.Event(), []

        async def slow(db, job_obj, trigger, deps=None):
            started.append(trigger)
            await gate.wait()
            return "run"

        scheduler.run_job = slow
        first = asyncio.create_task(scheduler.run_one(job.id, "schedule", self.factory(job)))
        await asyncio.sleep(0.05)
        self.assertTrue(scheduler.is_running(job.id))
        self.assertIsNone(await scheduler.run_one(job.id, "manual", self.factory(job)))      # refused, not queued
        gate.set()
        self.assertEqual(await first, "run")
        self.assertEqual(started, ["schedule"])
        self.assertFalse(scheduler.is_running(job.id))                                      # released afterwards

    async def test_the_job_is_released_even_when_the_run_raises(self):
        job = NS(id=uuid.uuid4())

        async def broken(db, job_obj, trigger, deps=None):
            raise RuntimeError("boom")

        scheduler.run_job = broken
        with self.assertRaises(RuntimeError):
            await scheduler.run_one(job.id, "schedule", self.factory(job))
        self.assertFalse(scheduler.is_running(job.id))

    async def test_the_loop_runs_due_jobs_survives_errors_and_stops_on_request(self):
        ran, ticks = [], []
        job_id = uuid.uuid4()

        async def fake_due(db, now):
            ticks.append(1)
            if len(ticks) == 1:
                raise RuntimeError("database hiccup")                        # the first tick fails: the loop must go on
            return [NS(id=job_id)] if len(ticks) == 2 else []

        async def fake_run_one(jid, trigger, session_factory=None, deps=None):
            ran.append((jid, trigger))

        async def no_interrupts(factory):
            return 0

        class Session:
            async def __aenter__(self):
                return NS()

            async def __aexit__(self, *a):
                return False

        scheduler.due_jobs, scheduler.mark_interrupted = fake_due, no_interrupts
        original_run_one = scheduler.run_one
        scheduler.run_one = fake_run_one
        stop = asyncio.Event()
        try:
            loop = asyncio.create_task(scheduler.scheduler_loop(stop, lambda: Session(), tick=0.02))
            await asyncio.sleep(0.2)
            stop.set()
            await asyncio.wait_for(loop, timeout=1)                          # stops promptly
        finally:
            scheduler.run_one = original_run_one
        self.assertGreaterEqual(len(ticks), 3)
        self.assertEqual(ran, [(job_id, "schedule")])


if __name__ == "__main__":
    unittest.main()
