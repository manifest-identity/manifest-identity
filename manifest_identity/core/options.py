"""Administrator settings: the choices an organization is allowed to
make, each with a secure default and an audit row per change (D-070).

The module is called options because `Settings` in core.config already
means the environment configuration a deployment supplies, and two
things called settings in one package is how a reader loses an hour.
The table is `settings`, the documents call these administrator
settings, and this module is where they are read and written.

Two rules give it its shape. The shipped default of every setting is
the secure one, so an organization that never opens the page has the
strict behaviour and one that relaxes it has decided to. And every
change writes an audit row in the same transaction as the change, so
"who turned justification off, and when" is answerable, which is the
question an auditor asks about a control that was on last quarter.

A key not in the registry cannot be written. The registry is the
surface, so a typo cannot quietly create a setting nothing reads.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.models import Setting, User


@dataclass(frozen=True)
class Option:
    key: str
    default: str
    kind: str  # bool | int
    description: str


# The authorization record's required fields and its lifetime bound.
# Justification and expiry ship required, which is D-070's ruling:
# the organization may turn them off, and turning one off is an
# audited act rather than a default nobody chose.
OPTIONS: dict[str, Option] = {
    o.key: o
    for o in (
        Option(
            "authorization.justification_required", "true", "bool",
            "An authorization must say why the access is needed.",
        ),
        Option(
            "authorization.reference_required", "false", "bool",
            "An authorization must carry a ticket or change reference.",
        ),
        Option(
            "authorization.control_reference_required", "false", "bool",
            "An authorization must name the control it satisfies, such as AC-2.",
        ),
        Option(
            "authorization.expiry_required", "true", "bool",
            "An authorization must end on a date rather than standing forever.",
        ),
        Option(
            "authorization.maximum_lifetime_days", "365", "int",
            "The furthest ahead an authorization may be set to expire.",
        ),
    )
}


class OptionError(ValueError):
    """A key that is not a setting, or a value the setting cannot take."""


def _row(db: Session, key: str) -> Setting | None:
    return db.execute(
        select(Setting).where(Setting.key == key)
    ).scalar_one_or_none()


def get(db: Session, key: str) -> str:
    """The stored value, or the shipped default when nobody has
    chosen. Reading never writes, so the absence of a row stays the
    honest statement that the default is in force."""
    option = OPTIONS.get(key)
    if option is None:
        raise OptionError(f"no such setting: {key}")
    row = _row(db, key)
    return row.value if row is not None else option.default


def get_bool(db: Session, key: str) -> bool:
    return get(db, key) == "true"


def get_int(db: Session, key: str) -> int:
    return int(get(db, key))


def validate(key: str, value: str) -> str:
    option = OPTIONS.get(key)
    if option is None:
        raise OptionError(f"no such setting: {key}")
    if option.kind == "bool":
        if value not in ("true", "false"):
            raise OptionError(f"{key} takes true or false")
        return value
    # An integer setting bounds something; a nonsense bound is worse
    # than the default, so the refusal is explicit rather than a cast
    # that raises somewhere later.
    if not value.isdigit() or not 1 <= int(value) <= 3650:
        raise OptionError(f"{key} takes a whole number of days from 1 to 3650")
    return value


def set_value(db: Session, key: str, value: str, actor: User) -> str:
    """Change one setting, with its audit row in the same transaction.
    The caller commits, so the change and the record land together or
    not at all."""
    value = validate(key, value)
    before = get(db, key)
    row = _row(db, key)
    if row is None:
        db.add(Setting(key=key, value=value, changed_by_username=actor.username))
    else:
        row.value = value
        row.changed_by_username = actor.username
    audit.record(
        db,
        actor_user_id=actor.id,
        actor_username=actor.username,
        action="setting_changed",
        target=key,
        detail=f"{before} to {value}",
    )
    return value


def current(db: Session) -> dict[str, str]:
    return {key: get(db, key) for key in OPTIONS}
