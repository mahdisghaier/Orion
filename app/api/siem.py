"""SIEM connection management — admin only.

- POST   /api/siem/          — create a connection (config encrypted before storage)
- GET    /api/siem/          — list connections (metadata only, never raw config)
- GET    /api/siem/{id}      — get one connection's metadata
- POST   /api/siem/{id}/test — check that a connection is reachable and authenticated
- DELETE /api/siem/{id}      — deactivate a connection (soft delete)
"""
import time
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_config
from app.core.database import get_db
from app.core.deps import require_admin
from app.models import SIEMConnection, User
from app.schemas import SIEMConnectionCreate, SIEMConnectionResponse, SIEMConnectionTestResult
from app.services.connectors.factory import ConnectorError, get_connector

router = APIRouter()


@router.post("/", response_model=SIEMConnectionResponse, status_code=status.HTTP_201_CREATED)
async def create_siem_connection(
    payload: SIEMConnectionCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Register a new SIEM connection. Config is encrypted before storage."""
    if payload.type == "wazuh":
        missing = [k for k in ("url", "username", "password") if not payload.config.get(k)]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"Wazuh config requires: url, username, password (missing: {', '.join(missing)})",
            )
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


@router.post("/{connection_id}/test", response_model=SIEMConnectionTestResult)
async def test_siem_connection(
    connection_id: UUID,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Check a stored connection end to end (decrypt config, reach the SIEM, authenticate)."""
    result = await db.execute(select(SIEMConnection).where(SIEMConnection.id == connection_id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise HTTPException(status_code=404, detail="SIEM connection not found")

    try:
        connector = get_connector(connection)
    except ConnectorError as e:
        return SIEMConnectionTestResult(success=False, message=str(e))

    started = time.perf_counter()
    ok = await connector.test_connection()
    latency_ms = int((time.perf_counter() - started) * 1000)
    return SIEMConnectionTestResult(
        success=ok,
        message="Connection OK" if ok else "Unreachable, authentication failed, or cluster unhealthy",
        latency_ms=latency_ms,
    )


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