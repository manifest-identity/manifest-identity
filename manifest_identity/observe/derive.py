"""The derivation engine: state from history, at read, never stored.

Everything shown about an identity is computed here from its
observations, relative to the scope's newest import capture time,
never the wall clock, so a month-old import shows month-old
staleness honestly instead of aging by itself (D-006). Sources carry
different fields, so the merged view takes each field from the newest
observation that actually carries it.

The shape is provider-neutral: an identity has a list of credentials,
each with its kind, whether it is active, its age, and its last use.
A provider with two access keys yields two rows; one with five yields
five. Findings iterate the list and never name a slot.
"""

from dataclasses import dataclass, field
from datetime import datetime

from manifest_identity.observe.models import (
    Credential,
    CredentialKind,
    IdentityObservation,
)

# An identity is not flaggable as unused until it has been watched long
# enough to mean it; a two-week-old key that has not been used yet is
# new, not stale (Repokid's eligibility lesson, via the prior art).
MIN_OBSERVATION_DAYS = 14

# Liveness older than this, against the as-of time, reads as unused.
UNUSED_AFTER_DAYS = 90


@dataclass
class CredentialState:
    kind: str
    label: str
    active: bool
    age_days: int | None
    last_used: datetime | None
    expires_at: datetime | None


@dataclass
class DerivedState:
    as_of: datetime
    observed_days: int
    display_name: str
    identity_type: str
    identity_created_at: datetime | None
    mfa_active: bool | None
    credentials: list[CredentialState] = field(default_factory=list)
    last_activity: datetime | None = None
    last_activity_days: int | None = None
    tags: object = None

    def active(self, kind: CredentialKind | str) -> list[CredentialState]:
        return [c for c in self.credentials if c.kind == kind and c.active]

    @property
    def password_enabled(self) -> bool:
        return bool(self.active(CredentialKind.password))

    @property
    def has_active_key(self) -> bool:
        return bool(self.active(CredentialKind.access_key))


@dataclass
class Classification:
    """Person or service, derived at read time from the credential
    shape and never stored (D-056). A person signs in with a password
    and a device; a service holds access keys and is offboarded by
    nobody, which is this tool's founding problem. An identity with
    both is the human use of a non-human credential the findings
    already name (NHI10)."""

    kind: str  # person, service, mixed, or unknown
    reason: str


def classify(state: DerivedState) -> Classification:
    if state.identity_type == "root":
        return Classification("person", "the root account is a person's sign-in")
    if state.identity_type == "role":
        return Classification("service", "a role is assumed, never signed into")
    keys = state.has_active_key
    password = state.password_enabled
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
    observations: list[tuple[IdentityObservation, datetime]],
    credentials: list[tuple[Credential, datetime]],
    as_of: datetime,
) -> DerivedState:
    """observations and credentials: (row, its import's captured_at),
    any order. Credentials are taken from the newest import that
    carries any credential row for the identity, because a credential
    absent from the newest report is a credential that is gone."""
    ordered = sorted(observations, key=lambda pair: pair[1])
    newest = ordered[-1][0]

    def freshest(attr: str) -> object:
        for row, _ in reversed(ordered):
            value = getattr(row, attr)
            if value is not None:
                return value
        return None

    first_seen = ordered[0][1]
    # The set of credentials is the newest report's, because a
    # credential absent from the newest report is a credential that is
    # gone; each field of a credential comes from the freshest row that
    # carries it, the same rule the observation fields follow (D-006).
    latest_credential_capture = max((c for _, c in credentials), default=None)
    current_keys = {
        (row.kind, row.external_id)
        for row, captured in credentials
        if captured == latest_credential_capture
    }
    history = sorted(credentials, key=lambda pair: pair[1], reverse=True)

    def freshest_credential_field(key: tuple[str, str | None], attr: str) -> object:
        for row, _ in history:
            if (row.kind, row.external_id) == key:
                value = getattr(row, attr)
                if value is not None:
                    return value
        return None

    states: list[CredentialState] = []
    for key in sorted(current_keys, key=lambda k: (k[0], k[1] or "")):
        kind, label = key
        rotated = freshest_credential_field(key, "last_rotated") or freshest_credential_field(
            key, "created_at_provider"
        )
        last_used = freshest_credential_field(key, "last_used")
        expires = freshest_credential_field(key, "expires_at")
        active = freshest_credential_field(key, "active")
        states.append(
            CredentialState(
                kind=kind,
                label=label or kind,
                active=bool(active),
                age_days=_days(as_of, rotated) if isinstance(rotated, datetime) else None,
                last_used=last_used if isinstance(last_used, datetime) else None,
                expires_at=expires if isinstance(expires, datetime) else None,
            )
        )
    activity = [c.last_used for c in states if isinstance(c.last_used, datetime)]
    observed_activity = freshest("last_activity")
    if isinstance(observed_activity, datetime):
        activity.append(observed_activity)
    last_activity = max(activity) if activity else None
    created = freshest("identity_created_at")
    return DerivedState(
        as_of=as_of,
        observed_days=_days(as_of, first_seen),
        display_name=newest.display_name,
        identity_type="",  # the caller knows; filled by the route layer
        identity_created_at=created if isinstance(created, datetime) else None,
        mfa_active=freshest("mfa_active"),  # type: ignore[arg-type]
        credentials=states,
        last_activity=last_activity,
        last_activity_days=(
            _days(as_of, last_activity) if last_activity else None
        ),
        tags=freshest("tags"),
    )
