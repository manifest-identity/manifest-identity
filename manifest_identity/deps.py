"""Request dependencies: who is calling, and are they allowed.

Authentication and authorization answer with different codes on
purpose: 401 means "no valid session," 403 means "a valid session
whose role this route does not admit," and the 403 body names the
roles that would be admitted, because an authenticated user deserves
an answer they can act on.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, params
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.db import get_session
from manifest_identity.models import AuthSession, User
from manifest_identity.ratelimit import WRITE_LIMITER
from manifest_identity.roles import ROUTE_ROLES
from manifest_identity.security import hash_token

_bearer = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    user: User
    session: AuthSession


def _authenticate(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_session)],
) -> AuthContext:
    if credentials is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    row = db.execute(
        select(AuthSession, User)
        .join(User, AuthSession.user_id == User.id)
        .where(AuthSession.token_hash == hash_token(credentials.credentials))
    ).first()
    if row is None:
        raise HTTPException(status_code=401, detail="invalid or expired session")
    session, user = row
    expires = session.expires_at
    # The unit-test database stores naive datetimes; normalize to UTC.
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if session.revoked_at is not None or expires <= datetime.now(UTC):
        raise HTTPException(status_code=401, detail="invalid or expired session")
    return AuthContext(user=user, session=session)


CurrentAuth = Annotated[AuthContext, Depends(_authenticate)]


def _throttle_writes(auth: CurrentAuth) -> AuthContext:
    """The write budget (D-041): heavy authenticated writes are bounded
    per user. 429 states the rule and repeats nothing the caller sent."""
    key = f"write:{auth.user.username}"
    if not WRITE_LIMITER.allowed(key):
        raise HTTPException(
            status_code=429,
            detail="write budget exceeded; wait a minute and continue",
        )
    WRITE_LIMITER.record_failure(key)
    return auth


ThrottledWrite = Annotated[AuthContext, Depends(_throttle_writes)]


def require_roles(route_key: str) -> params.Depends:
    """The matrix-driven authorization dependency.

    The key must exist in ROUTE_ROLES at import time, so a typo fails
    the process at startup rather than leaving a route unguarded.
    """
    if route_key not in ROUTE_ROLES:
        raise LookupError(f"route key not in ROUTE_ROLES: {route_key}")
    allowed = ROUTE_ROLES[route_key]

    def check(auth: CurrentAuth) -> AuthContext:
        if auth.user.role not in allowed:
            names = ", ".join(sorted(r.value for r in allowed))
            raise HTTPException(status_code=403, detail=f"requires role: {names}")
        return auth

    dependency: params.Depends = Depends(check)
    return dependency
