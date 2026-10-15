"""Hunts API — create, run, list, and inspect hunts."""
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Hunt, HuntResult, User
from app.schemas import HuntCreate, HuntResponse, HuntResultResponse, PaginatedResponse
from app.services.corroboration import enrich_findings
from app.services.hunt_runner import HuntRunner, HuntRunnerError

router = APIRouter()


@router.post("/", response_model=HuntResponse, status_code=status.HTTP_201_CREATED)
async def create_hunt(
    hunt_data: HuntCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create and run a hunt."""
    if not hunt_data.rule_id and not hunt_data.rule_yaml:
        raise HTTPException(
            status_code=422,
            detail="Either rule_id or rule_yaml must be provided"
        )

    runner = HuntRunner(db)
    try:
        hunt = await runner.create_and_run(
            created_by=current_user.id,
            siem_targets=hunt_data.siem_targets,
            rule_id=hunt_data.rule_id,
            rule_yaml=hunt_data.rule_yaml,
            time_range=hunt_data.time_range,
        )
    except HuntRunnerError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hunt failed: {e}")

    await log_action(db, user_id=current_user.id, action="hunt.create", target_type="hunt", target_id=hunt.id,
                     metadata={"status": hunt.status, "findings": hunt.total_hits, "siems": len(hunt.siem_targets),
                               "from_saved_rule": bool(hunt_data.rule_id)}, request=request)
    await db.commit()
    return hunt


@router.get("/", response_model=PaginatedResponse)
async def list_hunts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List hunts with pagination."""
    query = select(Hunt)
    count_query = select(func.count(Hunt.id))

    if status_filter:
        query = query.where(Hunt.status == status_filter)
        count_query = count_query.where(Hunt.status == status_filter)

    total = (await db.execute(count_query)).scalar()
    offset = (page - 1) * page_size
    result = await db.execute(
        query.order_by(Hunt.created_at.desc()).offset(offset).limit(page_size)
    )
    hunts = result.scalars().all()

    return {
        "items": [HuntResponse.model_validate(h) for h in hunts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": offset + page_size < total,
    }


@router.get("/{hunt_id}", response_model=HuntResponse)
async def get_hunt(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get details of a single hunt."""
    hunt = (await db.execute(select(Hunt).where(Hunt.id == hunt_id))).scalar_one_or_none()
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return hunt


@router.get("/{hunt_id}/results", response_model=List[HuntResultResponse])
async def get_hunt_results(
    hunt_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get findings for a specific hunt."""
    hunt = (await db.execute(select(Hunt).where(Hunt.id == hunt_id))).scalar_one_or_none()
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    result = await db.execute(
        select(HuntResult)
        .where(HuntResult.hunt_id == hunt_id)
        .order_by(HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc())
        .offset(offset)
        .limit(limit)
    )
    return await enrich_findings(db, result.scalars().all())
