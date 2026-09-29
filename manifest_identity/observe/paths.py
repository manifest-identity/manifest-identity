"""How access actually reaches an identity, computed at read.

Most privilege does not arrive directly. It arrives through a group, or
through a role the identity is allowed to assume, and an inventory that
lists only what is attached to a principal reports a fraction of what
that principal can do. This module expands the observed facts into the
paths access travels, with every hop named and carrying its own mode.

Nothing here is stored. The importer writes what the provider's file
says, one row per import: which policies are attached to which
principal, who is a member of which group, and which principals a role
trusts. Whether a user can reach an administrator policy through a
group, or by assuming a role that holds it, is derived from those rows
the moment somebody asks, which is the same rule the rest of the
product follows: nothing observed is edited, and nothing derived is
stored.

The split that matters to a reviewer is holds now against can obtain. A
policy attached to a user is privilege that user has this second. A
policy attached to a role that user may assume is privilege the user can
take whenever it chooses, without asking anyone, and it is invisible in
the identity's own grant list. Both are real; conflating them hides the
second, and treating them alike overstates the first.

Chains are bounded at TRUST_HOPS. A role may trust a role that trusts a
role, and an estate can carry a cycle; the bound keeps expansion finite
and the result says when it stopped rather than pretending it reached
the end.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.observe.models import (
    Grant,
    GrantMode,
    Identity,
    IdentityObservation,
    Membership,
    ObservedRelationship,
    RoleDefinition,
)

# How far a trust chain is followed. Two is enough for every arrangement
# seen so far, a principal assuming a role that can assume another, and
# it makes a cycle finite without an explicit visited set doing the work
# alone.
TRUST_HOPS = 2

# The hop kinds, which are the vocabulary a page reads back to a person.
VIA_DIRECT = "direct"
VIA_MEMBERSHIP = "membership"
VIA_TRUST = "trust"


@dataclass(frozen=True)
class Hop:
    """One step access takes. `via` is how the step is made, `ref` is
    what it is made through as the provider names it, and `mode` is
    whether the step is standing or has to be taken deliberately."""

    via: str
    ref: str
    mode: str

    def as_dict(self) -> dict[str, str]:
        return {"via": self.via, "ref": self.ref, "mode": self.mode}


@dataclass
class AccessPath:
    """One definition an identity can exercise, and the route to it."""

    role_definition_id: int
    role_name: str
    role_ref: str
    scope_node_id: int
    mode: str
    hops: list[Hop] = field(default_factory=list)
    source_kind: str = ""

    @property
    def holds_now(self) -> bool:
        """Standing access needs no further action by anyone."""
        return self.mode == GrantMode.standing

    @property
    def through(self) -> str:
        """The hop that makes this path worth reading, for a list that
        has room for one word: the last step that was not direct."""
        for hop in reversed(self.hops):
            if hop.via != VIA_DIRECT:
                return hop.via
        return VIA_DIRECT

    def as_dict(self) -> dict[str, object]:
        return {
            "role_definition_id": self.role_definition_id,
            "role": self.role_name,
            "role_ref": self.role_ref,
            "scope_node_id": self.scope_node_id,
            "mode": self.mode,
            "through": self.through,
            "path": [hop.as_dict() for hop in self.hops],
            "source_kind": self.source_kind,
        }


def _grants_for(db: Session, import_id: int, identity_ids: list[int]) -> list[Grant]:
    if not identity_ids:
        return []
    return list(
        db.execute(
            select(Grant).where(
                Grant.import_id == import_id,
                Grant.identity_id.in_(identity_ids),
            )
        ).scalars()
    )


def _definitions(db: Session, ids: set[int]) -> dict[int, RoleDefinition]:
    if not ids:
        return {}
    return {
        definition.id: definition
        for definition in db.execute(
            select(RoleDefinition).where(RoleDefinition.id.in_(ids))
        ).scalars()
    }


def _groups_of(db: Session, import_id: int, identity_id: int) -> list[Membership]:
    return list(
        db.execute(
            select(Membership).where(
                Membership.import_id == import_id,
                Membership.member_id == identity_id,
            )
        ).scalars()
    )


def references_of(db: Session, import_id: int, identity: Identity) -> set[str]:
    """Every string a trust policy could name this identity by.

    A policy names principals the way the provider writes them, which is
    the reference rather than the immutable identifier this product keys
    on, so the reference comes from what the import observed. An
    account-wide principal names every identity in that account, so the
    account's own form is included and the account is read from the
    reference rather than assumed.
    """
    reference = db.execute(
        select(IdentityObservation.provider_ref)
        .where(
            IdentityObservation.import_id == import_id,
            IdentityObservation.identity_id == identity.id,
        )
        .limit(1)
    ).scalar()
    if not reference:
        return set()
    references = {reference}
    parts = reference.split(":")
    # arn:partition:service:region:account:resource
    if len(parts) > 5 and parts[4]:
        references.add(f"arn:{parts[1]}:iam::{parts[4]}:root")
    return references


def _assumable_by(
    db: Session, import_id: int, identity: Identity
) -> list[ObservedRelationship]:
    """Roles this identity is named in the trust policy of.

    The importer records one relationship per principal in the document,
    so matching is on the principal string the provider wrote.
    """
    references = references_of(db, import_id, identity)
    if not references:
        return []
    relationships = list(
        db.execute(
            select(ObservedRelationship).where(
                ObservedRelationship.import_id == import_id,
                ObservedRelationship.kind.in_(("trust", "federation")),
            )
        ).scalars()
    )
    matches = []
    for relationship in relationships:
        if relationship.from_kind == "wildcard":
            # Anyone at all, which is a finding rather than a path for
            # one identity, and it is not silently turned into one here.
            continue
        if relationship.from_ref in references:
            matches.append(relationship)
    return matches


def _reachable_roles(
    db: Session, import_id: int, identity: Identity
) -> list[tuple[Identity, list[Hop]]]:
    """Roles this identity can assume, and the chain of assumptions that
    reaches each one.

    A role may trust a role, so reachability is a walk rather than a
    lookup, and an estate can name a cycle, so the walk is bounded at
    TRUST_HOPS and refuses to visit an identity twice. What comes back
    is each role with the hops taken to arrive at it, which is what makes
    the answer explainable rather than only true.
    """
    found: list[tuple[Identity, list[Hop]]] = []
    visited = {identity.id}
    frontier: list[tuple[Identity, list[Hop]]] = [(identity, [])]
    for _ in range(TRUST_HOPS):
        onward: list[tuple[Identity, list[Hop]]] = []
        for current, hops in frontier:
            for relationship in _assumable_by(db, import_id, current):
                if relationship.to_identity_id is None:
                    continue
                role = db.get(Identity, relationship.to_identity_id)
                if role is None or role.id in visited:
                    continue
                visited.add(role.id)
                chain = [*hops, Hop(VIA_TRUST, role.first_display_name, "assumable")]
                found.append((role, chain))
                onward.append((role, chain))
        if not onward:
            break
        frontier = onward
    return found


def for_identity(
    db: Session, *, import_id: int, identity: Identity
) -> list[AccessPath]:
    """Every definition this identity can exercise at this import, each
    with the route to it and whether it holds now or can obtain it."""
    paths: list[AccessPath] = []

    direct = _grants_for(db, import_id, [identity.id])
    group_rows = _groups_of(db, import_id, identity.id)
    groups = {
        group.id: group
        for group in db.execute(
            select(Identity).where(
                Identity.id.in_([row.group_id for row in group_rows])
            )
        ).scalars()
    }
    through_groups = _grants_for(db, import_id, list(groups))

    reachable = _reachable_roles(db, import_id, identity)
    through_roles = _grants_for(db, import_id, [role.id for role, _ in reachable])

    wanted = {
        grant.role_definition_id
        for grant in direct + through_groups + through_roles
    }
    definitions = _definitions(db, wanted)

    def add(grant: Grant, hops: list[Hop], mode: str) -> None:
        definition = definitions.get(grant.role_definition_id)
        if definition is None:
            return
        paths.append(
            AccessPath(
                role_definition_id=definition.id,
                role_name=definition.display_name_last,
                role_ref=definition.external_id,
                scope_node_id=grant.scope_node_id,
                mode=mode,
                hops=hops,
                source_kind=grant.source_kind,
            )
        )

    for grant in direct:
        add(grant, [Hop(VIA_DIRECT, "", "active")], grant.mode)

    for row in group_rows:
        group = groups.get(row.group_id)
        if group is None:
            continue
        # An eligible membership is access the member activates, so
        # everything reached through it is eligible however the group
        # holds it.
        mode = GrantMode.standing if row.mode == "active" else GrantMode.eligible
        for grant in [g for g in through_groups if g.identity_id == group.id]:
            add(
                grant,
                [
                    Hop(VIA_MEMBERSHIP, group.first_display_name, row.mode),
                    Hop(VIA_DIRECT, "", "active"),
                ],
                mode,
            )

    for role, chain in reachable:
        # Assuming a role is always a deliberate act, so everything
        # reached through one is access the identity can obtain rather
        # than access it holds, whatever the role holds it by.
        for grant in [g for g in through_roles if g.identity_id == role.id]:
            add(grant, [*chain, Hop(VIA_DIRECT, "", "active")], GrantMode.eligible)

    return paths


def split(paths: list[AccessPath]) -> tuple[list[AccessPath], list[AccessPath]]:
    """Holds now, and can obtain. The order a page reads them in."""
    return (
        [path for path in paths if path.holds_now],
        [path for path in paths if not path.holds_now],
    )
