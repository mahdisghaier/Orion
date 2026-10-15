"""The SOC inbox: notes from background jobs.

- GET  /api/notifications/                    newest first (?unread=true for unacknowledged only)
- GET  /api/notifications/summary             unread count and the worst unread severity, for the badge
- POST /api/notifications/{id}/acknowledge    mark one as seen
- POST /api/notifications/acknowledge-all     mark all as seen
"""
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Notification, User
from app.schemas import NotificationResponse

router = APIRouter()
_SEVERITY_ORDER = {"critical": 3, "warning": 2, "info": 1}


@router.get("/", response_model=list[NotificationResponse])
async def list_notifications(unread: bool = False, limit: int = 50, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = select(Notification).order_by(Notification.created_at.desc()).limit(max(1, min(limit, 200)))
    if unread:
        query = query.where(Notification.acknowledged_at.is_(None))
    return (await db.execute(query)).scalars().all()


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(Notification.severity, func.count()).where(Notification.acknowledged_at.is_(None)).group_by(Notification.severity)
    )).all()
    counts = {severity: n for severity, n in rows}
    worst = max(counts, key=lambda s: _SEVERITY_ORDER[s]) if counts else None
    return {"unread": sum(counts.values()), "by_severity": counts, "worst": worst}


@router.post("/acknowledge-all")
async def acknowledge_all(request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = await db.execute(
        update(Notification).where(Notification.acknowledged_at.is_(None))
        .values(acknowledged_at=datetime.now(timezone.utc), acknowledged_by=current_user.id)
    )
    await log_action(db, user_id=current_user.id, action="notification.acknowledge_all", metadata={"count": result.rowcount}, request=request)
    await db.commit()
    return {"acknowledged": result.rowcount}


@router.post("/{notification_id}/acknowledge", response_model=NotificationResponse)
async def acknowledge(notification_id: UUID, request: Request, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    note = await db.get(Notification, notification_id)
    if note is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    if note.acknowledged_at is None:
        note.acknowledged_at, note.acknowledged_by = datetime.now(timezone.utc), current_user.id
        await log_action(db, user_id=current_user.id, action="notification.acknowledge", target_type="notification", target_id=note.id, request=request)
        await db.commit()
    return note
