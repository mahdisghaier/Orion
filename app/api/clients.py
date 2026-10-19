"""Clients (tenants of the SOC).

- POST  /api/clients/        create a client (platform-wide administrator)
- GET   /api/clients/        the clients the caller may see (all for platform-wide staff, their own otherwise)
- PATCH /api/clients/{id}    rename or deactivate a client (platform-wide administrator)
"""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user, require_platform_admin
from app.models import Client, User
from app.schemas import ClientCreate, ClientResponse
from app.core.tenancy import user_client

router = APIRouter()


class ClientUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    is_active: bool | None = None


@router.post("/", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(payload: ClientCreate, request: Request, current_user: User = Depends(require_platform_admin),
                        db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(Client).where(Client.name == payload.name))).scalar_one_or_none():
        raise HTTPException(status_code=400, detail="A client with this name already exists")
    client = Client(name=payload.name)
    db.add(client)
    await db.flush()
    await log_action(db, user_id=current_user.id, action="client.create", target_type="client", target_id=client.id,
                     metadata={"name": client.name}, request=request)
    await db.commit()
    await db.refresh(client)
    return client


@router.get("/", response_model=list[ClientResponse])
async def list_clients(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = select(Client).order_by(Client.created_at)
    if user_client(current_user) is not None:
        query = query.where(Client.id == user_client(current_user))
    return (await db.execute(query)).scalars().all()


@router.patch("/{client_id}", response_model=ClientResponse)
async def update_client(client_id: UUID, payload: ClientUpdate, request: Request,
                        current_user: User = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)):
    client = await db.get(Client, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="Client not found")
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(client, field, value)
    await log_action(db, user_id=current_user.id, action="client.update", target_type="client", target_id=client.id,
                     metadata=changes, request=request)
    await db.commit()
    await db.refresh(client)
    return client
