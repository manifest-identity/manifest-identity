"""Configuration fails fast: a missing required key raises immediately."""

import pytest
from pydantic import ValidationError

from manifest_identity.config import Settings


def test_missing_database_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MANIFEST_IDENTITY_DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings()


def test_present_database_url_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANIFEST_IDENTITY_DATABASE_URL", "postgresql+psycopg://example")
    settings = Settings()
    assert settings.database_url.startswith("postgresql+psycopg://")


def test_log_level_defaults_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MANIFEST_IDENTITY_DATABASE_URL", "postgresql+psycopg://example")
    monkeypatch.delenv("MANIFEST_IDENTITY_LOG_LEVEL", raising=False)
    assert Settings().log_level == "INFO"
