"""FastAPI dependencies for authentication + RBAC.

Usage:
    @router.get("/me")
    async def me(current_user: User = Depends(get_current_user)):
        return current_user

    @router.post("/users/")
    async def create_user(
        user: UserCreate,
        current_user: User = Depends(require_role("admin"))
    ):
        ...
"""
from typing import Optional, Callable
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token
from app.models import User


# [explain] Used on every protected address. It finds the ticket (in the cookie, or in an Authorization header),
# [explain] checks it, and loads the user from the database. No valid ticket means 401 (not allowed in).
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract + verify the JWT from the access_token cookie.

    Raises 401 if:
        - No access_token cookie present
        - Token is invalid or expired
        - User does not exist or is inactive
    """
    # 1. Get token from httpOnly cookie (preferred)
    token = request.cookies.get("access_token")

    # 2. Fallback: Authorization header (for Swagger UI + programmatic clients)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Decode + verify
    claims = decode_token(token)
    if not claims or claims.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    # 4. Load user from DB
    try:
        user_id = UUID(claims["sub"])
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


# [explain] Builds a bouncer: only users whose role is in the allowed list get through, the others get 403.
def require_role(*allowed_roles: str) -> Callable:
    """Dependency factory: require the user to have one of the allowed roles.

    Usage:
        @router.delete("/users/{id}")
        async def delete_user(
            id: UUID,
            current_user: User = Depends(require_role("admin"))
        ):
            ...
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(allowed_roles)}. You have: {current_user.role}",
            )
        return current_user
    return role_checker


# Convenience aliases
# [explain] Ready-made bouncers: admin only, L2 and above, L3 and above.
require_admin = require_role("admin")
require_l2_plus = require_role("soc_l2", "soc_l3", "admin")
require_l3_plus = require_role("soc_l3", "admin")
