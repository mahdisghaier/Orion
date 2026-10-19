"""Clients (tenants): who may see and create what.

A user is either bound to one client (`client_id` set: an analyst or administrator of that customer) or
platform-wide (`client_id` NULL: the SOC's own staff, who work for every client). A bound user only ever
sees the rows of their client, and an object of another client answers 404, exactly as if it did not
exist, so that its identifier reveals nothing.
"""
from typing import Optional
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Client, User


def user_client(user: User) -> Optional[UUID]:
    """The client a user is bound to, or None for platform-wide staff."""
    return getattr(user, "client_id", None)


def scoped(query, column, user: User, client: Optional[UUID] = None):
    """Restrict a query to the user's client. Platform-wide users see everything, or one client when they ask."""
    bound = user_client(user)
    if bound is not None:
        return query.where(column == bound)
    if client is not None:
        return query.where(column == client)
    return query


def visible(row, user: User) -> bool:
    bound = user_client(user)
    return bound is None or getattr(row, "client_id", None) == bound


def ensure_visible(row, user: User, what: str = "Object"):
    """Return the row, or raise 404 when it does not exist or belongs to another client."""
    if row is None or not visible(row, user):
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return row


async def default_client_id(db: AsyncSession) -> UUID:
    """The client new objects go to when a platform-wide user does not name one and only one client exists."""
    clients = (await db.execute(select(Client.id).where(Client.is_active.is_(True)).order_by(Client.created_at))).scalars().all()
    if len(clients) == 1:
        return clients[0]
    raise HTTPException(status_code=422, detail="Select the client this work is for")


async def client_for_new_object(db: AsyncSession, user: User, requested: Optional[UUID] = None) -> UUID:
    """The client a new object belongs to. A bound user can only create for their own client."""
    bound = user_client(user)
    if bound is not None:
        if requested is not None and requested != bound:
            raise HTTPException(status_code=403, detail="You can only work for your own client")
        return bound
    if requested is not None:
        client = await db.get(Client, requested)
        if client is None or not client.is_active:
            raise HTTPException(status_code=404, detail="Client not found")
        return requested
    return await default_client_id(db)


async def client_of_connections(db: AsyncSession, user: User, connection_ids, requested: Optional[UUID] = None) -> UUID:
    """The client that owns every given connection. A hunt, an investigation or a job never mixes clients.

    A bound user gets 404 for a connection of another client. A platform-wide user gets 422 when the connections
    belong to several clients, because their results would end up in one client's list."""
    from app.models import SIEMConnection
    ids = set(connection_ids)
    rows = (await db.execute(select(SIEMConnection.id, SIEMConnection.client_id).where(SIEMConnection.id.in_(ids)))).all()
    bound = user_client(user)
    if len(rows) != len(ids) or (bound is not None and any(c != bound for _, c in rows)):
        raise HTTPException(status_code=404, detail="SIEM connection not found")
    owners = {c for _, c in rows}
    if len(owners) != 1:
        raise HTTPException(status_code=422, detail="Select the connections of one client only")
    owner = owners.pop()
    if requested is not None and requested != owner:
        raise HTTPException(status_code=422, detail="client_id does not match the targeted connections")
    return owner


async def active_connection_ids(db: AsyncSession, user: User, requested: Optional[UUID] = None) -> list:
    """The active connections a user may work with (all of them for platform-wide staff, one client's otherwise)."""
    from app.models import SIEMConnection
    query = scoped(select(SIEMConnection.id).where(SIEMConnection.is_active.is_(True)), SIEMConnection.client_id, user, requested)
    return list((await db.execute(query)).scalars().all())
