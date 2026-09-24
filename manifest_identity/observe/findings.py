"""Credential findings: the risk vocabulary, derived, never stored.

Each rule reads the derived state and either stays silent or produces a
finding that explains itself with the numbers that triggered it. Tiers
are the triage order a human works in: critical means act now, warning
means review this cycle, notice means context. Every finding carries
its external anchor, the OWASP Non-Human Identities Top 10 (2025)
identifier, so the vocabulary lines up with the published one
(COMPLIANCE.md's frameworks-to-features row).
"""

from dataclasses import dataclass

from manifest_identity.observe.derive import MIN_OBSERVATION_DAYS, UNUSED_AFTER_DAYS, DerivedState
from manifest_identity.observe.models import CredentialKind

KEY_AGE_WARNING_DAYS = 365
KEY_AGE_NOTICE_DAYS = 90


@dataclass
class Finding:
    code: str
    tier: str  # critical | warning | notice
    anchor: str  # OWASP NHI identifier
    explanation: str


def evaluate(state: DerivedState) -> list[Finding]:
    found: list[Finding] = []

    if state.identity_type == "root" and state.last_activity is not None:
        found.append(Finding(
            code="root_used",
            tier="critical",
            anchor="NHI10",
            explanation=(
                f"the root account was used {state.last_activity_days} days "
                "before this snapshot; root has no reason to sign in during "
                "normal operation"
            ),
        ))

    if state.password_enabled and state.mfa_active is False:
        found.append(Finding(
            code="password_without_mfa",
            tier="critical",
            anchor="NHI4",
            explanation=(
                "a console password is enabled with no multi-factor device; "
                "one phished or reused password is the whole account"
            ),
        ))

    for key in state.active(CredentialKind.access_key):
        label, age = key.label, key.age_days
        if age is not None:
            if age >= KEY_AGE_WARNING_DAYS:
                found.append(Finding(
                    code="key_age",
                    tier="warning",
                    anchor="NHI7",
                    explanation=(
                        f"the {label} access key is {age} days old; a key "
                        "that old has outlived every rotation policy"
                    ),
                ))
            elif age >= KEY_AGE_NOTICE_DAYS:
                found.append(Finding(
                    code="key_age",
                    tier="notice",
                    anchor="NHI7",
                    explanation=(
                        f"the {label} access key is {age} days old, past the "
                        "ninety day line"
                    ),
                ))

    if len(state.active(CredentialKind.access_key)) > 1:
        found.append(Finding(
            code="multiple_active_keys",
            tier="warning",
            anchor="NHI7",
            explanation=(
                "both access keys are active; rotation leaves one, two "
                "active keys usually means a rotation that never finished"
            ),
        ))

    if state.active(CredentialKind.certificate):
        found.append(Finding(
            code="legacy_certificate",
            tier="warning",
            anchor="NHI7",
            explanation=(
                "an X.509 signing certificate is active, a legacy "
                "credential most estates have forgotten they hold"
            ),
        ))

    if (
        state.identity_type != "root"
        and state.observed_days >= MIN_OBSERVATION_DAYS
        and (
            state.last_activity_days is None
            or state.last_activity_days >= UNUSED_AFTER_DAYS
        )
        and (
            state.password_enabled
            or state.has_active_key
            or state.identity_type == "role"
        )
    ):
        used = (
            f"last activity {state.last_activity_days} days before this snapshot"
            if state.last_activity_days is not None
            else "no recorded activity at all"
        )
        found.append(Finding(
            code="unused_identity",
            tier="warning",
            anchor="NHI1",
            explanation=(
                f"{used}, watched for {state.observed_days} days; an "
                "identity nobody uses is an identity nobody will miss "
                "until an attacker does"
            ),
        ))

    return found
