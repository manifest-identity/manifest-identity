"""Application configuration.

Every required key fails fast: a missing value stops the process at
startup with a clear error, rather than surfacing later as a confusing
failure mid-request. Optional keys carry their default here, so this
file is the complete inventory of what configures the application.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MANIFEST_IDENTITY_")

    # Required: no default, so a missing value raises at startup.
    database_url: str

    # Optional, with the default visible here.
    log_level: str = "INFO"

    # Sessions expire this long after sign-in, absolute, not sliding:
    # a stolen token has a bounded life no matter how actively it is used.
    session_ttl_hours: int = 12

    # When both are set, startup creates this administrator if no user
    # with that name exists, and never touches an existing one.
    admin_username: str | None = None
    admin_password: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Build settings once and reuse them.

    The cache means the fail-fast check runs exactly once, at first use,
    which the application arranges to be startup.
    """
    # The arguments come from the environment; the checker cannot see that.
    return Settings()  # type: ignore[call-arg]
