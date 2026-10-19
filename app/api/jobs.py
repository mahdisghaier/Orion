"""Scheduled threat-intelligence checks.

- GET    /api/jobs/                         the jobs, with their latest run
- POST   /api/jobs/                         create one (admin)
- PATCH  /api/jobs/{id}                     enable, disable, change interval or settings (admin)
- DELETE /api/jobs/{id}                     delete a job and its runs (admin)
- POST   /api/jobs/{id}/run                 run it now, in the background (L2+)
- GET    /api/jobs/{id}/runs                run history
- GET    /api/jobs/runs/{run_id}            one run with its full summary
- GET    /api/jobs/runs/{run_id}/report.pdf the run's PDF report
"""
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user, require_admin, require_l2_plus
from app.core.tenancy import client_for_new_object, ensure_visible, scoped
from app.models import JobRun, ScheduledJob, User
from app.schemas import JobCreate, JobResponse, JobRunBrief, JobRunResponse, JobUpdate
from app.services.scheduler import is_running, run_one
from app.services.threat_intel.report import build_intel_report_pdf
from app.services.threat_intel.runner import clean_custom_iocs

router = APIRouter()
_background: set = set()          # keeps references to running tasks so they are not garbage collected


def _brief(run: JobRun) -> JobRunBrief:
    return JobRunBrief(id=run.id, status=run.status, trigger=run.trigger, started_at=run.started_at, finished_at=run.finished_at,
                       headline=(run.summary or {}).get("headline"), error=run.error)


async def _latest_run(db: AsyncSession, job_id: UUID):
    return (await db.execute(select(JobRun).where(JobRun.job_id == job_id).order_by(JobRun.started_at.desc()).limit(1))).scalar_one_or_none()


async def _response(db: AsyncSession, job: ScheduledJob) -> JobResponse:
    latest = await _latest_run(db, job.id)
    return JobResponse(
        id=job.id, client_id=job.client_id, name=job.name, kind=job.kind, interval_hours=job.interval_hours, enabled=job.enabled, config=job.config,
        created_at=job.created_at, last_run_at=job.last_run_at, next_run_at=job.next_run_at,
        running=is_running(job.id), latest_run=_brief(latest) if latest else None,
    )


def _config_dict(config) -> dict:
    data = config.model_dump()
    data["custom_iocs"] = clean_custom_iocs(data.get("custom_iocs") or {})     # drop anything that is not a valid indicator
    return data


async def _get_job(db: AsyncSession, job_id: UUID, user: User) -> ScheduledJob:
    return ensure_visible(await db.get(ScheduledJob, job_id), user, "Job")


@router.get("/", response_model=list[JobResponse])
async def list_jobs(client_id: Optional[UUID] = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    jobs = (await db.execute(scoped(select(ScheduledJob), ScheduledJob.client_id, current_user, client_id).order_by(ScheduledJob.created_at))).scalars().all()
    return [await _response(db, j) for j in jobs]


@router.post("/", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(payload: JobCreate, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_admin)):
    job = ScheduledJob(
        client_id=await client_for_new_object(db, current_user, payload.client_id),
        name=payload.name, kind=payload.kind, interval_hours=payload.interval_hours, enabled=payload.enabled,
        config=_config_dict(payload.config), created_by=current_user.id,
        next_run_at=datetime.now(timezone.utc) + timedelta(minutes=1),            # first run shortly after creation
    )
    db.add(job)
    await db.flush()
    await log_action(db, user_id=current_user.id, action="job.create", target_type="job", target_id=job.id,
                     metadata={"name": job.name, "interval_hours": job.interval_hours}, request=request)
    await db.commit()
    return await _response(db, job)


@router.get("/runs/{run_id}", response_model=JobRunResponse)
async def get_run(run_id: UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = await db.get(JobRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await _get_job(db, run.job_id, current_user)          # a run belongs to its job's client
    return run


@router.get("/runs/{run_id}/report.pdf")
async def get_run_report(run_id: UUID, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    run = await db.get(JobRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    job = await _get_job(db, run.job_id, current_user)
    pdf = build_intel_report_pdf(job.name if job else "Threat-intelligence check", run)
    await log_action(db, user_id=current_user.id, action="job.report", target_type="job_run", target_id=run.id, metadata={"status": run.status}, request=request)
    await db.commit()
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="threat-intel-{str(run.id)[:8]}.pdf"'})


@router.patch("/{job_id}", response_model=JobResponse)
async def update_job(job_id: UUID, payload: JobUpdate, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_admin)):
    job = await _get_job(db, job_id, current_user)
    changes = {}
    if payload.name is not None:
        job.name = changes["name"] = payload.name
    if payload.enabled is not None:
        job.enabled = changes["enabled"] = payload.enabled
    if payload.interval_hours is not None:
        job.interval_hours = changes["interval_hours"] = payload.interval_hours
        if job.last_run_at:
            job.next_run_at = job.last_run_at + timedelta(hours=job.interval_hours)
    if payload.config is not None:
        job.config = _config_dict(payload.config)
        changes["config"] = "changed"
    await log_action(db, user_id=current_user.id, action="job.update", target_type="job", target_id=job.id, metadata=changes, request=request)
    await db.commit()
    return await _response(db, job)


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(job_id: UUID, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_admin)):
    job = await _get_job(db, job_id, current_user)
    await log_action(db, user_id=current_user.id, action="job.delete", target_type="job", target_id=job.id, metadata={"name": job.name}, request=request)
    await db.delete(job)
    await db.commit()


@router.post("/{job_id}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_job_now(job_id: UUID, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_l2_plus)):
    job = await _get_job(db, job_id, current_user)
    if is_running(job.id):
        raise HTTPException(status_code=409, detail="This job is already running")
    await log_action(db, user_id=current_user.id, action="job.run", target_type="job", target_id=job.id, metadata={"trigger": "manual"}, request=request)
    await db.commit()
    task = asyncio.create_task(run_one(job.id, "manual"))
    _background.add(task)
    task.add_done_callback(_background.discard)
    return {"status": "started", "message": "The check runs in the background; refresh the run list in a moment."}


@router.get("/{job_id}/runs", response_model=list[JobRunBrief])
async def list_runs(job_id: UUID, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    await _get_job(db, job_id, current_user)
    runs = (await db.execute(select(JobRun).where(JobRun.job_id == job_id).order_by(JobRun.started_at.desc()).limit(50))).scalars().all()
    return [_brief(r) for r in runs]
