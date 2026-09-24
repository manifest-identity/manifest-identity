"""Review campaigns: the workflow that turns findings into decisions.

Three rules give this module its shape. The population is frozen at
creation: the scope resolves to items once, with each item carrying
the evidence as it stood, so the campaign reviews a stated population
rather than a moving one. The machine recommends and never decides: a
recommendation names its reasons and waits for a person, and there is
no operation anywhere that disposes more than one item, because a
certification records that someone looked at that identity (D-039).
And "insufficient evidence" is an honest first-class answer that names
what was missing, because the alternative is a reviewer forced to
certify what they could not see, which produces approvals nobody
meant.
"""

from dataclasses import dataclass

from manifest_identity.observe.derive import MIN_OBSERVATION_DAYS
from manifest_identity.observe.findings import Finding

SCOPES = ("everything", "privileged", "flagged", "users", "roles")

RECURRENCES = ("none", "monthly", "quarterly", "yearly")

DISPOSITIONS = (
    "certify",
    "revoke_recommended",
    "insufficient_evidence",
    "delegated",
)

# Dispositions whose meaning is incomplete without a note: what was
# missing, or who now holds the question.
NOTE_REQUIRED = ("insufficient_evidence", "delegated")

# Finding codes that argue for revocation rather than mere attention:
# unused means the access is not earning its risk, and root use means
# the identity should not be in day-to-day hands at all.
REVOKE_CODES = frozenset({"unused_identity", "root_used"})


@dataclass
class Recommendation:
    verdict: str  # certify | revoke_recommended | insufficient_evidence
    reasons: list[str]


def recommend(
    findings: list[Finding], observed_days: int
) -> Recommendation:
    """The engine's answer, always with its reasons, never the decision.

    Order matters: too little history outranks everything, because a
    recommendation built on four days of observation is a guess presented
    as a verdict. Then revocation signals, then the tier weight, then the
    quiet default.
    """
    if observed_days < MIN_OBSERVATION_DAYS:
        return Recommendation(
            verdict="insufficient_evidence",
            reasons=[
                f"observed for {observed_days} day(s), less than the "
                f"{MIN_OBSERVATION_DAYS} day minimum the derivation "
                "engine requires before liveness means anything"
            ],
        )
    revoke = [f for f in findings if f.code in REVOKE_CODES]
    if revoke:
        return Recommendation(
            verdict="revoke_recommended",
            reasons=[f.explanation for f in revoke],
        )
    critical = [f for f in findings if f.tier == "critical"]
    if critical:
        return Recommendation(
            verdict="revoke_recommended",
            reasons=[f.explanation for f in critical],
        )
    warnings = [f for f in findings if f.tier == "warning"]
    if warnings:
        return Recommendation(
            verdict="certify",
            reasons=(
                ["no revocation signal, with open warnings to weigh:"]
                + [f.explanation for f in warnings]
            ),
        )
    return Recommendation(
        verdict="certify",
        reasons=["no finding above notice; the record argues for keeping it"],
    )


def evidence_delta(
    previous: dict[str, object] | None, current: dict[str, object] | None
) -> list[str]:
    """What changed since the last certification, in plain statements.

    This is what the reviewer actually reviews: re-reading everything a
    quarter produces approval without attention, and the delta is the part
    that needs a fresh decision.
    """
    if not isinstance(previous, dict) or not isinstance(current, dict):
        return []
    out: list[str] = []

    def codes(evidence: dict[str, object]) -> set[str]:
        found = evidence.get("finding_codes")
        return set(found) if isinstance(found, list) else set()

    appeared = sorted(codes(current) - codes(previous))
    resolved = sorted(codes(previous) - codes(current))
    for code in appeared:
        out.append(f"finding appeared since last certification: {code}")
    for code in resolved:
        out.append(f"finding resolved since last certification: {code}")

    if previous.get("owner") != current.get("owner"):
        out.append(
            f"owner changed from {previous.get('owner') or 'nobody'} "
            f"to {current.get('owner') or 'nobody'}"
        )

    def sources(evidence: dict[str, object]) -> set[str]:
        held = evidence.get("privilege_sources")
        return set(held) if isinstance(held, list) else set()

    gained = sorted(sources(current) - sources(previous))
    lost = sorted(sources(previous) - sources(current))
    for source in gained:
        out.append(f"privilege gained since last certification: {source}")
    for source in lost:
        out.append(f"privilege lost since last certification: {source}")
    return out
