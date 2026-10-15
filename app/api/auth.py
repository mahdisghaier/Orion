"""Authentication endpoints.

- POST /api/auth/login    — exchange email+password for JWT cookies
- POST /api/auth/refresh  — exchange refresh token for new access token
- POST /api/auth/logout   — clear cookies
- GET  /api/auth/me       — get current user info
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.audit import log_action
from app.core.deps import get_current_user
from app.core.login_guard import login_guard
from app.core.security import (
    create_access_token, create_refresh_token, decode_token,
    generate_csrf_token, verify_password,
    get_access_cookie_params, get_refresh_cookie_params, get_csrf_cookie_params,
)
from app.models import User
from app.schemas import LoginRequest, RefreshRequest, Token, UserResponse

router = APIRouter()


@router.post("/login", response_model=Token)
async def login(
    request: LoginRequest,
    response: Response,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate and set JWT cookies.

    Returns token metadata in the body (without the actual token,
    which lives in the httpOnly cookie for security).
    """
    address = http_request.client.host if http_request.client else "unknown"
    wait = login_guard.retry_after(request.email, address)
    if wait:
        await log_action(db, user_id=None, action="auth.login_blocked", metadata={"email": request.email[:200]}, request=http_request)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(wait)},
        )

    # 1. Find user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    # 2. Verify password
    if not user or not verify_password(request.password, user.password_hash):
        login_guard.failure(request.email, address)
        await log_action(db, user_id=None, action="auth.login_failed", metadata={"email": request.email[:200]}, request=http_request)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    login_guard.success(request.email)
    await log_action(db, user_id=user.id, action="auth.login", target_type="user", target_id=user.id, request=http_request)
    await db.commit()

    # 3. Create tokens
    access_token = create_access_token(str(user.id), user.role)
    refresh_token = create_refresh_token(str(user.id), user.role)
    csrf_token = generate_csrf_token()

    # 4. Set cookies (httpOnly + SameSite=Strict)
    response.set_cookie(value=access_token, **get_access_cookie_params())
    response.set_cookie(value=refresh_token, **get_refresh_cookie_params())
    response.set_cookie(value=csrf_token, **get_csrf_cookie_params())

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=15 * 60,
    )


@router.post("/refresh", response_model=Token)
async def refresh(
    request: RefreshRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new access token."""
    claims = decode_token(request.refresh_token)
    if not claims or claims.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    try:
        user_id = claims["sub"]
    except KeyError:
        raise HTTPException(status_code=401, detail="Invalid token claims")

    # Verify user still exists + is active
    from uuid import UUID
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Issue new access token
    access_token = create_access_token(str(user.id), user.role)
    response.set_cookie(value=access_token, **get_access_cookie_params())

    return Token(
        access_token=access_token,
        refresh_token=request.refresh_token,  # refresh token not rotated in MVP
        expires_in=15 * 60,
    )


@router.post("/logout")
async def logout(response: Response):
    """Clear all auth cookies."""
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token", path="/api/auth/refresh")
    response.delete_cookie("csrf_token")
    return {"message": "Logged out"}


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return current_user
