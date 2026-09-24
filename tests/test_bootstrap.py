"""Bootstrap converges: present after one run, unchanged after two."""

import secrets

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core.bootstrap import bootstrap_admin
from manifest_identity.core.config import Settings
from manifest_identity.core.security import PasswordPolicyError
from manifest_identity.models import User

GOOD_PASSWORD = "pw-" + secrets.token_urlsafe(16)


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "database_url": "sqlite+pysqlite:///:memory:",
        "admin_username": "boot.admin",
        "admin_password": GOOD_PASSWORD,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_two_runs_one_admin(client: object, db: Session) -> None:
    settings = _settings()
    bootstrap_admin(db, settings)
    bootstrap_admin(db, settings)
    rows = db.execute(select(User).where(User.username == "boot.admin")).scalars().all()
    assert len(rows) == 1
    from manifest_identity.core.scope import roles_held
    assert roles_held(db, rows[0]) == {"administrator"}


def test_existing_user_is_never_modified(client: object, db: Session) -> None:
    settings = _settings()
    bootstrap_admin(db, settings)
    original_hash = db.execute(select(User.password_hash)).scalar_one()
    bootstrap_admin(db, _settings(admin_password="pw2-" + secrets.token_urlsafe(16)))
    assert db.execute(select(User.password_hash)).scalar_one() == original_hash


def test_unconfigured_bootstrap_skips(client: object, db: Session) -> None:
    bootstrap_admin(db, _settings(admin_username=None, admin_password=None))
    assert db.execute(select(User)).scalars().all() == []


def test_policy_violating_password_stops_startup(client: object, db: Session) -> None:
    settings = _settings(admin_password="short")  # noqa: S106  (deliberately invalid, tests the policy gate)
    with pytest.raises(PasswordPolicyError):
        bootstrap_admin(db, settings)
