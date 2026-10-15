"""CSRF protection by double submit.

At login the server sets a csrf_token cookie that JavaScript can read. Every state-changing request that
relies on the login cookie must repeat that value in the X-CSRF-Token header. A page on another site can
make the browser SEND the cookies but cannot READ them, so it cannot build the header.

SameSite=Strict on the cookies already blocks most cross-site requests; this check is the second layer and
makes the claim in the design true instead of decorative.

Not applied to: safe methods (GET, HEAD, OPTIONS), the login route (no cookie exists yet), and requests that
authenticate with an Authorization header (a header is not sent automatically by a browser, so it is not CSRF-able).
"""
import secrets
from typing import Mapping

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
EXEMPT_PATHS = {"/api/auth/login"}


def csrf_ok(method: str, path: str, cookies: Mapping[str, str], headers: Mapping[str, str]) -> bool:
    if method.upper() in SAFE_METHODS or not path.startswith("/api/") or path in EXEMPT_PATHS:
        return True
    if not cookies.get("access_token"):
        return True                      # not cookie-authenticated: nothing for an attacker's page to ride on
    expected = cookies.get("csrf_token", "")
    sent = headers.get("x-csrf-token", "")
    if not expected or not sent:
        return False
    return secrets.compare_digest(expected.encode("utf-8"), sent.encode("utf-8"))
