"""Database plumbing.

One engine per process, sessions handed out per request. Models declare
against Base; Alembic owns the schema, so create_all never runs here.
"""

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from manifest_identity.core.config import get_settings


class Base(DeclarativeBase):
    pass


@lru_cache
def get_engine() -> Engine:
    # pool_pre_ping replaces stale pooled connections instead of handing
    # them to a request to fail with.
    return create_engine(get_settings().database_url, pool_pre_ping=True)


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    maker = sessionmaker(bind=get_engine())
    session = maker()
    try:
        yield session
    finally:
        session.close()


def database_reachable() -> bool:
    """One round trip, used by the readiness route."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        # Readiness reports availability, never the failure detail; the
        # detail goes nowhere near a response body.
        return False
