"""Assembling an identity's privilege picture, with attribution.

Every capability names where it came from, because "this account is
over-privileged" is an accusation and "this account can rewrite its own
policy, through the automation group's PowerUserAccess" is a finding
somebody can act on. Groups are privilege sources, never actors
(D-019), so a user's picture is its own policies plus the policies of
every group it belongs to, each source labeled.

The readings underneath state their limits; those limits ride along
into the findings here rather than being quietly dropped.
"""

from dataclasses import dataclass, field

from manifest_identity.observe.findings import Finding
from manifest_identity.observe.policy_analysis import (
    PolicyReading,
    TrustReading,
    read_policy,
    read_trust_policy,
)

OWNER_TAG_KEYS = ("owner", "Owner", "owner_team", "team", "Team", "contact")


@dataclass
class PolicyIndex:
    """Every policy document one snapshot recorded, by identifier."""

    managed: dict[str, object] = field(default_factory=dict)
    # owner's immutable provider identifier -> {policy name: document}
    inline: dict[str, dict[str, object]] = field(default_factory=dict)


@dataclass
class GroupFacts:
    name: str
    key: str  # the provider's immutable group identifier
    attached: list[dict[str, str]] = field(default_factory=list)
    inline_names: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)


@dataclass
class PrivilegeSource:
    policy: str
    via: str  # "directly" or "through the <name> group"
    reading: PolicyReading

    def describe(self) -> str:
        return f"{self.policy}, held {self.via}"


@dataclass
class PrivilegePicture:
    sources: list[PrivilegeSource] = field(default_factory=list)
    combined: PolicyReading = field(default_factory=PolicyReading)
    owner: str | None = None
    trust: TrustReading | None = None

    def sources_for(self, predicate: str) -> list[str]:
        """Which sources carry a given capability, for attribution."""
        out = []
        for source in self.sources:
            value = getattr(source.reading, predicate)
            if value:
                out.append(source.describe())
        return out


def _owner_from_tags(tags: object) -> str | None:
    if not isinstance(tags, dict):
        return None
    for key in OWNER_TAG_KEYS:
        value = tags.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def read_identity_privilege(
    *,
    identity_key: str,
    tags: object,
    attached: object,
    group_names: object,
    trust_policy: object,
    account_id: str,
    index: PolicyIndex,
    groups: dict[str, GroupFacts],
) -> PrivilegePicture:
    picture = PrivilegePicture(owner=_owner_from_tags(tags))

    def add(policy_name: str, via: str, document: object) -> None:
        reading = read_policy(document)
        picture.sources.append(PrivilegeSource(policy_name, via, reading))
        picture.combined = picture.combined.merge(reading)

    if isinstance(attached, list):
        for entry in attached:
            if isinstance(entry, dict) and isinstance(entry.get("arn"), str):
                add(
                    str(entry.get("name") or entry["arn"]),
                    "directly",
                    index.managed.get(entry["arn"]),
                )

    for name, document in (index.inline.get(identity_key, {}) or {}).items():
        add(f"inline policy {name}", "directly", document)

    if isinstance(group_names, list):
        for group_name in group_names:
            group = groups.get(str(group_name))
            if group is None:
                continue
            via = f"through the {group.name} group"
            for entry in group.attached:
                if isinstance(entry, dict) and isinstance(entry.get("arn"), str):
                    add(
                        str(entry.get("name") or entry["arn"]),
                        via,
                        index.managed.get(entry["arn"]),
                    )
            for name, document in (index.inline.get(group.key, {}) or {}).items():
                add(f"inline policy {name}", via, document)

    if trust_policy is not None:
        picture.trust = read_trust_policy(trust_policy, account_id)

    return picture


def _limits(reading: PolicyReading) -> str:
    """The honest caveat, attached where the claim is made."""
    notes = []
    if reading.has_deny:
        notes.append("a deny statement is present and is not evaluated here")
    if reading.conditioned:
        notes.append("a condition is present and is not evaluated here")
    return "; " + ", ".join(notes) if notes else ""


def evaluate_privilege(picture: PrivilegePicture) -> list[Finding]:
    found: list[Finding] = []
    combined = picture.combined
    caveat = _limits(combined)

    if combined.admin_equivalent:
        sources = picture.sources_for("admin_equivalent")
        found.append(Finding(
            code="admin_equivalent",
            tier="critical",
            anchor="NHI5",
            explanation=(
                "holds administrator-equivalent privilege through "
                f"{'; '.join(sources)}: every action on every resource"
                f"{caveat}"
            ),
        ))

    # Escalation is reported for identities that are not already
    # administrators. An administrator can obviously reach every
    # escalation path, so listing them there buries the finding that
    # matters: the principal nobody calls an administrator that can
    # become one. That is the shadow admin the heuristics exist to find.
    if combined.escalation and not combined.admin_equivalent:
        sources = picture.sources_for("escalation")
        found.append(Finding(
            code="privilege_escalation_capable",
            tier="critical",
            anchor="NHI5",
            explanation=(
                "is not an administrator but can become one: "
                + "; ".join(combined.escalation)
                + f". Granted by {'; '.join(sources)}{caveat}"
            ),
        ))

    if combined.iam_mutating and not combined.admin_equivalent:
        sources = picture.sources_for("iam_mutating")
        found.append(Finding(
            code="iam_mutating",
            tier="warning",
            anchor="NHI5",
            explanation=(
                "can change identity and access management objects through "
                f"{'; '.join(sources)}; a principal that edits access "
                f"controls the boundary it sits inside{caveat}"
            ),
        ))

    if (
        combined.wildcard_write
        and combined.wildcard_resource
        and not combined.admin_equivalent
    ):
        sources = picture.sources_for("wildcard_write")
        found.append(Finding(
            code="wildcard_privilege",
            tier="warning",
            anchor="NHI5",
            explanation=(
                "holds wildcard actions that can change things, on wildcard "
                f"resources, through {'; '.join(sources)}: broader than any "
                f"stated purpose can justify{caveat}"
            ),
        ))
    elif (
        combined.wildcard_action
        and combined.wildcard_resource
        and not combined.admin_equivalent
    ):
        sources = picture.sources_for("wildcard_action")
        found.append(Finding(
            code="broad_read",
            tier="notice",
            anchor="NHI5",
            explanation=(
                "can read across every resource through "
                f"{'; '.join(sources)}: ordinary for a reporting identity, "
                f"and worth confirming in an account holding sensitive data"
                f"{caveat}"
            ),
        ))

    if combined.negated_allow:
        sources = picture.sources_for("negated_allow")
        found.append(Finding(
            code="everything_except_grant",
            tier="notice",
            anchor="NHI5",
            explanation=(
                "is granted everything except a named list, through "
                f"{'; '.join(sources)}, so it gains whatever the provider "
                f"adds next{caveat}"
            ),
        ))

    trust = picture.trust
    if trust is not None:
        if trust.public:
            found.append(Finding(
                code="trust_public",
                tier="critical",
                anchor="NHI6",
                explanation=(
                    "its trust policy admits any principal"
                    + (
                        ", narrowed by a condition this reading does not "
                        "evaluate" if trust.conditioned else
                        ", with no condition narrowing it"
                    )
                ),
            ))
        if trust.cross_account:
            found.append(Finding(
                code="trust_cross_account",
                tier="notice" if trust.conditioned else "warning",
                anchor="NHI6",
                explanation=(
                    "can be assumed from outside this account, by "
                    + ", ".join(trust.cross_account)
                    + (
                        ", with a condition present (the vendor pattern, "
                        "worth confirming the vendor is current)"
                        if trust.conditioned
                        else ", with no condition present"
                    )
                ),
            ))

    if picture.owner is None and combined.privileged:
        found.append(Finding(
            code="unowned_privileged",
            tier="warning",
            anchor="NHI1",
            explanation=(
                "carries privilege and names no owner in its tags, so no "
                "one can answer for it and nobody will offboard it"
            ),
        ))

    return found


def evaluate_group(
    group: GroupFacts, index: PolicyIndex, tags: object = None
) -> tuple[PolicyReading, list[Finding]]:
    """Groups get their own findings: a privileged group is a standing
    grant, and an empty one is a grant waiting for its first member."""
    reading = PolicyReading()
    for entry in group.attached:
        if isinstance(entry, dict) and isinstance(entry.get("arn"), str):
            reading = reading.merge(read_policy(index.managed.get(entry["arn"])))
    for document in (index.inline.get(group.key, {}) or {}).values():
        reading = reading.merge(read_policy(document))

    found: list[Finding] = []
    if reading.privileged and not group.members:
        found.append(Finding(
            code="empty_privileged_group",
            tier="notice",
            anchor="NHI5",
            explanation=(
                f"the {group.name} group grants privilege and has no "
                "members: a standing grant waiting for whoever is added "
                "next, and nobody reviewing it today"
            ),
        ))
    if reading.privileged and _owner_from_tags(tags) is None:
        found.append(Finding(
            code="unowned_privileged_group",
            tier="warning",
            anchor="NHI1",
            explanation=(
                f"the {group.name} group grants privilege to "
                f"{len(group.members)} member(s) and names no owner"
            ),
        ))
    return reading, found


def membership_drift(
    group_name: str, previous: list[str], current: list[str]
) -> list[Finding]:
    """What changed since the last snapshot, which is what a reviewer
    reviews; re-reading everything produces approval without attention."""
    added = sorted(set(current) - set(previous))
    removed = sorted(set(previous) - set(current))
    if not added and not removed:
        return []
    parts = []
    if added:
        parts.append(f"{len(added)} added")
    if removed:
        parts.append(f"{len(removed)} removed")
    return [Finding(
        code="membership_drift",
        tier="notice",
        anchor="NHI5",
        explanation=(
            f"the {group_name} group's membership changed since the "
            f"previous snapshot: {', '.join(parts)}"
        ),
    )]
