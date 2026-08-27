"""SIEM connection management — admin only.

- POST   /api/siem/          — create a connection (config encrypted before storage)
- GET    /api/siem/          — list connections (metadata only, never raw config)
- GET    /api/siem/{id}      — get one connection's metadata
- DELETE /api/siem/{id}      — deactivate a connection (soft delete)
"""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_config
from app.core.database import get_db
from app.core.deps import require_admin
from app.models import SIEMConnection, User
from app.schemas import SIEMConnectionCreate, SIEMConnectionResponse

router = APIRouter()


@router.post("/", response_model=SIEMConnectionResponse, status_code=status.HTTP_201_CREATED)
async def create_siem_connection(
    payload: SIEMConnectionCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Register a new SIEM connection. Config is encrypted before storage."""
    connection = SIEMConnection(
        name=payload.name,
        type=payload.type,
        config_encrypted=encrypt_config(payload.config),
        created_by=current_user.id,
        is_active=True,
    )
    db.add(connection)
    await db.commit()
    await db.refresh(connection)
    return connection


@router.get("/", response_model=list[SIEMConnectionResponse])
async def list_siem_connections(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all SIEM connections (metadata only — config never returned)."""
    result = await db.execute(select(SIEMConnection).order_by(SIEMConnection.created_at.desc()))
    return result.scalars().all()


@router.get("/{connection_id}", response_model=SIEMConnectionResponse)
async def get_siem_connection(
    connection_id: UUID,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get a single SIEM connection's metadata."""
    result = await db.execute(select(SIEMConnection).where(SIEMConnection.id == connection_id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="SIEM connection not found")
    return connection


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_siem_connection(
    connection_id: UUID,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete: mark inactive rather than hard-delete.

    Preserves referential integrity — hunt_results.siem_connection_id
    may still reference this row for historical findings.
    """
    result = await db.execute(select(SIEMConnection).where(SIEMConnection.id == connection_id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="SIEM connection not found")

    connection.is_active = False
    await db.commit()