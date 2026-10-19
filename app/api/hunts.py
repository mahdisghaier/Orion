"""Hunts API — create, run, list, and inspect hunts."""
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import active_connection_ids, client_of_connections, ensure_visible, scoped, user_client
from app.models import Client, Hunt, HuntResult, User
from app.schemas import ClientHuntResult, HuntCreate, HuntResponse, HuntResultResponse, MultiHuntCreate, PaginatedResponse
from app.services.multi_hunt import hunt_every_client
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

    client_id = await client_of_connections(db, current_user, hunt_data.siem_targets, hunt_data.client_id)
    runner = HuntRunner(db)
    try:
        hunt = await runner.create_and_run(
            created_by=current_user.id,
            siem_targets=hunt_data.siem_targets,
            rule_id=hunt_data.rule_id,
            rule_yaml=hunt_data.rule_yaml,
            time_range=hunt_data.time_range,
            client_id=client_id,
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


@router.post("/by-client", response_model=List[ClientHuntResult])
async def hunt_for_every_client(
    payload: MultiHuntCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run one rule for each client the caller may work for: a separate hunt per client, never one across clients.

    Staff of the SOC (platform-wide) get every active client; a user bound to a client gets that client only."""
    if not payload.rule_id and not payload.rule_yaml:
        raise HTTPException(status_code=422, detail="Either rule_id or rule_yaml must be provided")
    query = select(Client).where(Client.is_active.is_(True)).order_by(Client.name)
    if user_client(current_user) is not None:
        query = query.where(Client.id == user_client(current_user))
    clients = (await db.execute(query)).scalars().all()

    async def connections_of(client_id):
        return await active_connection_ids(db, current_user, client_id)

    async def run(client_id, connection_ids):
        return await HuntRunner(db).create_and_run(
            created_by=current_user.id, siem_targets=connection_ids, rule_id=payload.rule_id,
            rule_yaml=payload.rule_yaml, time_range=payload.time_range, client_id=client_id)

    results = await hunt_every_client(clients, connections_of, run)
    await log_action(db, user_id=current_user.id, action="hunt.create_by_client", target_type="hunt",
                     metadata={"clients": len(results), "completed": sum(1 for r in results if r.status == "completed"),
                               "skipped": sum(1 for r in results if r.status == "skipped"),
                               "from_saved_rule": bool(payload.rule_id)}, request=request)
    await db.commit()
    return [ClientHuntResult(client_id=r.client_id, client_name=r.client_name, status=r.status, hunt_id=r.hunt_id,
                             total_hits=r.total_hits, note=r.note) for r in results]


@router.get("/", response_model=PaginatedResponse)
async def list_hunts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str = Query(None, alias="status"),
    client_id: Optional[UUID] = Query(None, description="platform-wide users: only this client"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List hunts with pagination."""
    query = scoped(select(Hunt), Hunt.client_id, current_user, client_id)
    count_query = scoped(select(func.count(Hunt.id)), Hunt.client_id, current_user, client_id)

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
    hunt = ensure_visible((await db.execute(select(Hunt).where(Hunt.id == hunt_id))).scalar_one_or_none(), current_user, "Hunt")
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
    hunt = ensure_visible((await db.execute(select(Hunt).where(Hunt.id == hunt_id))).scalar_one_or_none(), current_user, "Hunt")

    result = await db.execute(
        select(HuntResult)
        .where(HuntResult.hunt_id == hunt_id)
        .order_by(HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc())
        .offset(offset)
        .limit(limit)
    )
    return await enrich_findings(db, result.scalars().all())
