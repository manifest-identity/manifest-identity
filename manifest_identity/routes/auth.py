"""Sign-in, sign-out, and who-am-i.

The login path is shaped so that every failure looks the same from
outside: unknown username and wrong password run the same bcrypt cost
and return the same body, and the rate limiter answers before the
database is consulted at all.
"""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity import audit, security
from manifest_identity.config import get_settings
from manifest_identity.db import get_session
from manifest_identity.deps import CurrentAuth, require_roles
from manifest_identity.logs import log_event
from manifest_identity.models import AuthSession, User, utcnow
from manifest_identity.ratelimit import LOGIN_LIMITER

router = APIRouter(prefix="/auth")


class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class LoginResponse(BaseModel):
    token: str
    role: str
    expires_at: str


def _client_ip(request: Request) -> str:
    # The direct peer only. Forwarded-for headers are attacker-writable
    # and are not consulted; the deployment layer owns that translation.
    return request.client.host if request.client else "unknown"


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    db: Annotated[Session, Depends(get_session)],
) -> LoginResponse:
    ip = _client_ip(request)
    user_key = f"u:{body.username}"
    ip_key = f"ip:{ip}"
    if not (LOGIN_LIMITER.allowed(user_key) and LOGIN_LIMITER.allowed(ip_key)):
        # App log, not the audit table: rejected requests must not be
        # able to grow the audit table without bound.
        log_event("login_rate_limited", path="/auth/login")
        raise HTTPException(status_code=429, detail="too many attempts")

    user = db.execute(
        select(User).where(User.username == body.username)
    ).scalar_one_or_none()

    if user is None:
        # The unknown name pays the same bcrypt cost as a wrong password.
        security.verify_against_dummy(body.password)
    if user is None or not security.verify_password(body.password, user.password_hash):
        LOGIN_LIMITER.record_failure(user_key)
        LOGIN_LIMITER.record_failure(ip_key)
        # Bounded by the limiter: at most max_failures rows per key
        # per window reach the audit table.
        audit.record(
            db,
            actor_username=body.username,
            action="login_failure",
            ip=ip,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")

    LOGIN_LIMITER.reset(user_key)
    token, token_hash = security.new_session_token()
    expires = utcnow() + timedelta(hours=get_settings().session_ttl_hours)
    db.add(
        AuthSession(token_hash=token_hash, user_id=user.id, expires_at=expires)
    )
    audit.record(
        db,
        actor_user_id=user.id,
        actor_username=user.username,
        action="login_success",
        ip=ip,
    )
    db.commit()
    return LoginResponse(token=token, role=user.role, expires_at=expires.isoformat())


@router.post("/logout", dependencies=[require_roles("POST /auth/logout")])
def logout(
    auth: CurrentAuth, db: Annotated[Session, Depends(get_session)]
) -> dict[str, str]:
    # The dependency and this handler hold sessions from different
    # database connections; revoke by id in this one.
    row = db.get(AuthSession, auth.session.id)
    if row is not None and row.revoked_at is None:
        row.revoked_at = utcnow()
        audit.record(
            db,
            actor_user_id=auth.user.id,
            actor_username=auth.user.username,
            action="logout",
        )
        db.commit()
    return {"status": "signed out"}


@router.get("/me", dependencies=[require_roles("GET /auth/me")])
def me(auth: CurrentAuth) -> dict[str, str]:
    return {
        "username": auth.user.username,
        "role": auth.user.role,
        "session_expires_at": auth.session.expires_at.isoformat(),
    }
