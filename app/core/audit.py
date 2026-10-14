"""Audit logging — every state-changing user action is persisted to audit_log table.

Usage:
    from app.core.audit import log_action

    await log_action(
        db, user_id=current_user.id,
        action="user.create",
        target_type="user", target_id=new_user.id,
        metadata={"email": new_user.email, "role": new_user.role},
        request=request,  # captures IP + User-Agent
    )
"""
from typing import Optional
from uuid import UUID

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


# [explain] Writes one line in the diary: who did what, to which thing, when, and from which address.
# [explain] The line joins the caller's database transaction and is saved by the caller's commit, so the diary
# [explain] and the action it describes are saved together or not at all (no diary line for something that failed).
async def log_action(
    db: AsyncSession,
    *,
    user_id: Optional[UUID],
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[UUID] = None,
    metadata: Optional[dict] = None,
    request: Optional[Request] = None,
) -> None:
    """Add one audit log entry to the caller's transaction. The CALLER commits, so the entry and
    the action it records succeed or fail together."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        metadata_=metadata or {},
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("User-Agent", "")[:500] if request else None,
    )
    db.add(entry)
