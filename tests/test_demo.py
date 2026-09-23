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

    from manifest_identity import config, db

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
    assert "19 identities" in first

    # Second run: nothing new, nothing broken.
    assert demo.main() == 0
    second = capsys.readouterr().out
    assert "already imported" in second
    assert "campaign already present" in second
    assert "19 identities" in second


def test_demo_refuses_without_admin_env(demo_env, monkeypatch, capsys) -> None:
    monkeypatch.setenv("MANIFEST_IDENTITY_ADMIN_USERNAME", "")
    from manifest_identity import config

    config.get_settings.cache_clear()
    from manifest_identity import demo

    assert demo.main() == 1
    assert "MANIFEST_IDENTITY_ADMIN_USERNAME" in capsys.readouterr().out
