"""Authenticating an integration, which is not a person.

A session belongs to a user who signed in with a password and holds
roles at scopes. An integration token belongs to a system that reads:
a security information and event management system, a ticketing
system, a report. It is a second kind of credential, and it gets a
second dependency rather than a role in the matrix, so a token can never
reach a session route and a session can never reach a token route. The
two surfaces do not share a door (threat 17).

The token is stored as a hash the way sessions are, compared by hash,
and the plaintext is shown once at minting and never again. Every
request under a token is counted against that token's own budget, so
one integration polling too hard cannot starve the others or the page.

Demonstration-grade, and stated as such in the documents: enough to
show the shape, not yet hardened for anyone to rely on (the product
plan's open question on how hard the read API should be).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.api.models import IntegrationToken
from manifest_identity.core.db import get_session
from manifest_identity.core.models import utcnow
from manifest_identity.core.ratelimit import LoginRateLimiter
from manifest_identity.core.security import hash_token

_bearer = HTTPBearer(auto_error=False)

# Every request counts, not only failures, and the ceiling is per token
# rather than per address, because the thing being protected is the
# database's time and the thing being identified is the integration.
READ_LIMITER = LoginRateLimiter(max_failures=120, window_seconds=60)


@dataclass
class TokenContext:
    token: IntegrationToken


def _authenticate_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_session)],
) -> TokenContext:
    if credentials is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    row = db.execute(
        select(IntegrationToken).where(
            IntegrationToken.token_hash == hash_token(credentials.credentials)
        )
    ).scalar_one_or_none()
    # A session presented here matches nothing, which is the point: the
    # message is the same as for an unknown token, so the response does
    # not say which kind of credential it was.
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=401, detail="invalid or revoked token")
    key = f"token:{row.id}"
    if not READ_LIMITER.allowed(key):
        raise HTTPException(
            status_code=429,
            detail="read budget exceeded for this token; wait a minute and continue",
        )
    READ_LIMITER.record_failure(key)
    row.last_used_at = utcnow()
    db.commit()
    return TokenContext(token=row)


CurrentToken = Annotated[TokenContext, Depends(_authenticate_token)]
