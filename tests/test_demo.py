"""The demo command: one command to a populated instance, twice.

The property that matters is convergence: a first run builds the
populated state and a second run changes nothing and fails nothing,
because the README tells a stranger the command is safe to repeat.
"""

import importlib

import pytest


@pytest.fixture
def demo_env(tmp_path, monkeypatch):
    """A private on-disk database for the demo run, bypassing the
    suite's shared in-memory engine, which conftest installs by
    replacing the engine accessor outright."""
    url = f"sqlite+pysqlite:///{tmp_path}/demo.db"
    monkeypatch.setenv("MANIFEST_IDENTITY_DATABASE_URL", url)
    monkeypatch.setenv("MANIFEST_IDENTITY_ADMIN_USERNAME", "demo.admin")
    monkeypatch.setenv("MANIFEST_IDENTITY_ADMIN_PASSWORD", "demo-" + "x" * 12)
    from sqlalchemy import create_engine

    from manifest_identity.core import config, db

    config.get_settings.cache_clear()
    engine = create_engine(url)
    monkeypatch.setattr(db, "get_engine", lambda: engine)
    yield
    config.get_settings.cache_clear()


def test_demo_populates_and_converges(demo_env, capsys) -> None:
    from manifest_identity import demo

    importlib.reload(demo)
    assert demo.main() == 0
    first = capsys.readouterr().out
    assert "campaign created" in first
    assert "77 identities" in first
    assert "authorizations through the file door, 0 refused" in first

    # Second run: nothing new, nothing broken, and the record written
    # once is found and left alone.
    assert demo.main() == 0
    second = capsys.readouterr().out
    assert "already imported" in second
    assert "campaign already present" in second
    assert "77 identities" in second
    assert "record: 0 authorizations" in second


def test_the_populated_record_shows_every_class_of_difference(demo_env) -> None:
    """The point of the second record (1.16): a demo that shows an
    estate an administrator has worked on, with every class of
    difference present and most of what is held authorized."""
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from manifest_identity import demo
    from manifest_identity.compare import delta
    from manifest_identity.core import db as core_db
    from manifest_identity.core.models import User
    from manifest_identity.core.roles import Role
    from manifest_identity.core.scope import roles_held

    importlib.reload(demo)
    assert demo.main() == 0
    db = sessionmaker(bind=core_db.get_engine())()
    try:
        findings = delta.for_estate(db)
        counts = delta.counts(findings)
        definitions = delta.definition_counts(delta.for_definitions(db))
        for kind in (
            delta.HELD_NOT_AUTHORIZED, delta.ACCESS_VIA_UNAUTHORIZED_RELATIONSHIP,
            delta.EXPIRED_STILL_HELD, delta.ELIGIBLE_NOT_AUTHORIZED,
            delta.DEFINITION_CHANGED, delta.AUTHORIZED_NOT_HELD, delta.OWNER_DISAGREEMENT,
        ):
            assert counts[kind] >= 1, kind
        assert definitions[delta.CUSTOM_DEFINITION_CHANGED] >= 1
        assert definitions[delta.CUSTOM_DEFINITION_NOT_AUTHORIZED] >= 1
        # Most of what is held is authorized: the unauthorized list is a
        # list a person can read, not the whole estate.
        assert 10 <= counts[delta.HELD_NOT_AUTHORIZED] <= 40
        operator = db.execute(select(User).where(User.username == "demo.operator")).scalar_one()
        assert roles_held(db, operator) == {Role.operator}
    finally:
        db.close()


def test_demo_refuses_without_admin_env(demo_env, monkeypatch, capsys) -> None:
    monkeypatch.setenv("MANIFEST_IDENTITY_ADMIN_USERNAME", "")
    from manifest_identity.core import config

    config.get_settings.cache_clear()
    from manifest_identity import demo

    assert demo.main() == 1
    assert "MANIFEST_IDENTITY_ADMIN_USERNAME" in capsys.readouterr().out
