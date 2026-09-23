"""Test environment.

Unit tests run against an in-memory SQLite database created from the
models, which keeps the suite fast and dependency-free. The risk that
choice carries, models drifting from the real database's migrations,
is guarded in the pipeline, where Alembic upgrades a real PostgreSQL
and `alembic check` fails on any model-to-migration drift. Two
mechanisms, one honest split: logic is tested here, schema fidelity is
tested there.
"""

import os
from collections.abc import Iterator

os.environ.setdefault("MANIFEST_IDENTITY_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("MANIFEST_IDENTITY_ADMIN_USERNAME", "")
os.environ.setdefault("MANIFEST_IDENTITY_ADMIN_PASSWORD", "")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from manifest_identity import db as db_module
from manifest_identity.db import Base
from manifest_identity.ratelimit import LOGIN_LIMITER, WRITE_LIMITER
from manifest_identity.roles import Role
from manifest_identity.security import hash_password

# One shared in-memory database for the whole test process; StaticPool
# hands every connection the same underlying store.
_engine = create_engine(
    "sqlite+pysqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_maker = sessionmaker(bind=_engine)


def _test_get_session() -> Iterator[Session]:
    s = _maker()
    try:
        yield s
    finally:
        s.close()


# The app under test uses the test database through both entry points.
# Guarded for idempotence: a second execution of this module must not
# wrap the already-replaced engine.
if hasattr(db_module.get_engine, "cache_clear"):
    db_module.get_engine.cache_clear()
    db_module.get_engine = lambda: _engine  # type: ignore[assignment]

from manifest_identity.main import app  # noqa: E402  (after the engine override)

app.dependency_overrides[db_module.get_session] = _test_get_session

# Generated fresh every run, per the standing rule: no credential-shaped
# literal ever sits in a tracked file, test material included.
TEST_PASSWORD = "pw-" + __import__("secrets").token_urlsafe(16)

ROLE_USERS = {
    Role.reviewer: "test.reviewer",
    Role.operator: "test.operator",
    Role.administrator: "test.admin",
}


@pytest.fixture
def client() -> Iterator[TestClient]:
    Base.metadata.drop_all(_engine)
    Base.metadata.create_all(_engine)
    LOGIN_LIMITER.clear()
    WRITE_LIMITER.clear()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def db() -> Iterator[Session]:
    s = _maker()
    try:
        yield s
    finally:
        s.close()


def make_user(db: Session, role: Role, username: str | None = None) -> str:
    """Create a user directly in the database; returns the username."""
    from manifest_identity.models import User

    name = username or ROLE_USERS[role]
    db.add(
        User(
            username=name,
            password_hash=hash_password(TEST_PASSWORD),
            role=role.value,
        )
    )
    db.commit()
    return name


def login(client: TestClient, username: str) -> str:
    """Sign in and return the bearer token."""
    r = client.post(
        "/auth/login", json={"username": username, "password": TEST_PASSWORD}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
