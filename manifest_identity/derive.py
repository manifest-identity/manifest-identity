"""The derivation engine: state from history, at read, never stored.

Everything shown about an identity is computed here from its
observations, relative to the account's newest snapshot capture time,
never the wall clock, so a month-old import shows month-old staleness
honestly instead of aging by itself (D-006). The two import sources
carry different fields, so the merged view takes each field from the
newest observation that actually carries it.
"""

from dataclasses import dataclass
from datetime import datetime

from manifest_identity.models import Observation

# An identity is not flaggable as unused until it has been watched long
# enough to mean it; a two-week-old key that has not been used yet is
# new, not stale (Repokid's eligibility lesson, via the prior art).
MIN_OBSERVATION_DAYS = 14

# Liveness older than this, against the as-of time, reads as unused.
UNUSED_AFTER_DAYS = 90


@dataclass
class DerivedState:
    as_of: datetime
    observed_days: int
    display_name: str
    identity_type: str
    identity_created_at: datetime | None
    password_enabled: bool | None
    mfa_active: bool | None
    key1_active: bool | None
    key1_age_days: int | None
    key2_active: bool | None
    key2_age_days: int | None
    cert1_active: bool | None
    cert2_active: bool | None
    last_activity: datetime | None
    last_activity_days: int | None
    attached_policies: int
    inline_policies: int
    group_names: list[str]
    # The raw privilege inputs, each taken from the freshest
    # observation that carries it. Two sources can share a capture
    # time, so "the newest row" is not the same as "the newest value".
    tags: object = None
    attached_raw: object = None
    trust_policy: object = None


@dataclass
class Classification:
    """Person or service, derived at read time from the credential
    shape and never stored (issue 37). A person signs in with a
    password and a device; a service holds access keys and is
    offboarded by nobody, which is this tool's founding problem. An
    identity with both is the human use of a non-human credential
    the findings already name (NHI10)."""

    kind: str  # person, service, mixed, or unknown
    reason: str


def classify(state: DerivedState) -> Classification:
    if state.identity_type == "root":
        return Classification("person", "the root account is a person's sign-in")
    if state.identity_type == "role":
        return Classification("service", "a role is assumed, never signed into")
    keys = bool(state.key1_active or state.key2_active)
    password = bool(state.password_enabled)
    if password and keys:
        return Classification(
            "mixed", "a console password and active access keys on one identity")
    if password:
        return Classification(
            "person",
            "a console password" + (" with MFA" if state.mfa_active else " without MFA"))
    if keys:
        return Classification("service", "access keys and no console password")
    return Classification("unknown", "neither a console password nor an active key")


def _days(later: datetime, earlier: datetime) -> int:
    return max(0, (later - earlier).days)


def derive(
    observations: list[tuple[Observation, datetime]], as_of: datetime
) -> DerivedState:
    """observations: (row, its snapshot's captured_at), any order."""
    ordered = sorted(observations, key=lambda pair: pair[1])
    newest = ordered[-1][0]

    def freshest(field: str) -> object:
        for row, _ in reversed(ordered):
            value = getattr(row, field)
            if value is not None:
                return value
        return None

    first_seen = ordered[0][1]
    activity_candidates = [
        freshest("password_last_used"),
        freshest("key1_last_used"),
        freshest("key2_last_used"),
        freshest("role_last_used"),
    ]
    activity = [t for t in activity_candidates if isinstance(t, datetime)]
    last_activity = max(activity) if activity else None

    def age(field: str) -> int | None:
        value = freshest(field)
        return _days(as_of, value) if isinstance(value, datetime) else None

    created = freshest("identity_created_at")
    attached = freshest("attached_policies")
    inline = freshest("inline_policy_names")
    groups = freshest("group_names")
    return DerivedState(
        as_of=as_of,
        observed_days=_days(as_of, first_seen),
        display_name=newest.display_name,
        identity_type="",  # the caller knows; filled by the route layer
        identity_created_at=created if isinstance(created, datetime) else None,
        password_enabled=freshest("password_enabled"),  # type: ignore[arg-type]
        mfa_active=freshest("mfa_active"),  # type: ignore[arg-type]
        key1_active=freshest("key1_active"),  # type: ignore[arg-type]
        key1_age_days=age("key1_last_rotated"),
        key2_active=freshest("key2_active"),  # type: ignore[arg-type]
        key2_age_days=age("key2_last_rotated"),
        cert1_active=freshest("cert1_active"),  # type: ignore[arg-type]
        cert2_active=freshest("cert2_active"),  # type: ignore[arg-type]
        last_activity=last_activity,
        last_activity_days=(
            _days(as_of, last_activity) if last_activity else None
        ),
        attached_policies=len(attached) if isinstance(attached, list) else 0,
        inline_policies=len(inline) if isinstance(inline, list) else 0,
        group_names=list(groups) if isinstance(groups, list) else [],
        tags=freshest("tags"),
        attached_raw=attached,
        trust_policy=freshest("trust_policy"),
    )
