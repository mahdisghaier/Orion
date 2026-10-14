"""Authentication & security utilities.

- JWT creation/verification (access + refresh tokens)
- Bcrypt password hashing via passlib
- Cookie helpers for httpOnly + Secure + SameSite=Strict
- CSRF double-submit token generation

Bank-grade pattern: JWT in httpOnly cookie = immune to XSS.
CSRF double-submit = immune to CSRF without server-side session tracking.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import secrets

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ─── Password hashing ──────────────────────────────────────────
# [explain] We never store passwords. We store a scrambled version (a hash) that cannot be turned back.
# [explain] bcrypt is the scrambling recipe.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# [explain] Scramble a password before saving it.
def hash_password(password: str) -> str:
    """Hash a password for storage. Returns the bcrypt hash."""
    return pwd_context.hash(password)


# [explain] At login: scramble what the user typed and compare it with the saved scramble.
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ─── JWT tokens ────────────────────────────────────────────────
# [explain] A token is a signed ticket. It says who you are and when it stops being valid.
# [explain] Only our secret key can sign it, so nobody can forge one.
def _create_token(
    subject: str,
    role: str,
    expires_delta: timedelta,
    token_type: str,
    extra_claims: Optional[dict] = None,
) -> str:
    """Internal: create a signed JWT.

    Args:
        subject: user_id (as string)
        role: user role (admin | soc_l1 | soc_l2 | soc_l3)
        expires_delta: token lifetime
        token_type: 'access' or 'refresh'
        extra_claims: optional additional claims
    """
    to_encode = {
        "sub": subject,
        "role": role,
        "type": token_type,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + expires_delta,
    }
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# [explain] The short ticket (minutes). It is sent with every request.
def create_access_token(user_id: str, role: str) -> str:
    """Create a short-lived access token (15 min default)."""
    return _create_token(
        subject=user_id,
        role=role,
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )


# [explain] The long ticket (days). It is only used to get a new short ticket without typing the password again.
def create_refresh_token(user_id: str, role: str) -> str:
    """Create a long-lived refresh token (7 days default)."""
    return _create_token(
        subject=user_id,
        role=role,
        expires_delta=timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )


# [explain] Check a ticket: is the signature ours and is it still valid? If not, we return nothing.
def decode_token(token: str) -> Optional[dict]:
    """Decode + verify a JWT. Returns claims dict, or None if invalid/expired."""
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        return None


# ─── Cookie helpers ────────────────────────────────────────────
# Bank-grade: httpOnly + Secure + SameSite=Strict = immune to XSS
# (JS cannot read the cookie, so a stolen XSS payload can't steal the token)

# [explain] Settings for the cookie that carries the ticket.
# [explain] httponly: JavaScript cannot read it, so a bad script on the page cannot steal it.
# [explain] samesite=strict: other websites cannot make the browser send it.
def get_access_cookie_params() -> dict:
    """Cookie kwargs for the access token."""
    return {
        "key": "access_token",
        "httponly": True,
        "secure": settings.APP_ENV == "production",  # True in prod, False for localhost dev
        "samesite": "strict",
        "max_age": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "path": "/",  # available to all API routes
    }


def get_refresh_cookie_params() -> dict:
    """Cookie kwargs for the refresh token — scoped to /api/auth/refresh only."""
    return {
        "key": "refresh_token",
        "httponly": True,
        "secure": settings.APP_ENV == "production",
        "samesite": "strict",
        "max_age": settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        "path": "/api/auth/refresh",  # scoped: only sent on refresh requests
    }


def get_csrf_cookie_params() -> dict:
    """Cookie kwargs for the CSRF double-submit token — readable by JS."""
    return {
        "key": "csrf_token",
        "httponly": False,  # JS must read this to echo in X-CSRF-Token header
        "secure": settings.APP_ENV == "production",
        "samesite": "strict",
        "max_age": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "path": "/",
    }


# ─── CSRF ──────────────────────────────────────────────────────
# [explain] A random code used to prove that a request really came from our own page.
def generate_csrf_token() -> str:
    """Generate a random CSRF token for the double-submit pattern."""
    return secrets.token_urlsafe(32)
