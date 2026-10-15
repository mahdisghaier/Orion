"""User management — admin only.

- POST   /api/users/          — create a user (any role)
- GET    /api/users/          — list all users
- GET    /api/users/{id}      — get one user
- PATCH  /api/users/{id}      — update role/name/active status
"""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import require_admin
from app.core.security import hash_password
from app.models import User
from app.schemas import UserCreate, UserResponse, UserUpdate

router = APIRouter()


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user with any role. Admin only."""
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await log_action(db, user_id=current_user.id, action="user.create", target_type="user", target_id=user.id,
                     metadata={"email": user.email, "role": user.role}, request=request)
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/", response_model=list[UserResponse])
async def list_users(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all users. Admin only."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get a single user by ID. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    payload: UserUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's name, role, or active status. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    # the audit line records WHAT changed (field names and role/active values), never a password
    await log_action(db, user_id=current_user.id, action="user.update", target_type="user", target_id=user.id,
                     metadata={k: v for k, v in update_data.items() if k in ("role", "is_active", "full_name")}
                              | {"fields": sorted(update_data)}, request=request)
    await db.commit()
    await db.refresh(user)
    return user