"""Seeding the authorized record from the observed one.

Nobody types an identity's immutable identifier into a spreadsheet, and
nobody should have to write out what a system can already see. So the
observed grants are offered back in the shape an authorization takes:
on the page as a prefill for one grant, and as a file in the import's
own columns for a whole estate.

The rule that makes this safe is that it prefills and never writes. An
observed grant is what is; an authorization is what somebody decided
should be. Turning the first into the second without a person in the
middle would make the delta compare the observed record against a copy
of itself, which is a product that always says everything is fine
(D-024). Every route here produces a draft; a person authorizes it.

What is already authorized is marked, so the page can offer the action
on the grants that lack one rather than inviting a second answer to a
question already answered.
"""

import csv
import io
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.authorize import authorizations, csv_import
from manifest_identity.core.models import ScopeNode
from manifest_identity.observe.assessment import _newest_import_ids
from manifest_identity.observe.models import (
    Grant,
    Identity,
    IdentityKind,
    Membership,
    RoleDefinition,
)


@dataclass
class ObservedGrant:
    """One grant as the record would authorize it: the provider's
    vocabulary already ended at the parser, so these are the neutral
    fields the form and the file both take."""

    identity_id: int
    identity_external_id: str
    display_name: str
    account: str
    role_definition_external_id: str
    role_definition_hash: str | None
    role_display_name: str
    mode: str
    path: list[dict[str, str]]
    source_kind: str
    authorized: bool

    def path_text(self) -> str:
        """The compact form the file door reads back: blank for a
        direct hop, otherwise `via:ref` joined by `>`."""
        if len(self.path) == 1 and self.path[0].get("via") == "direct":
            return ""
        return ">".join(
            hop.get("via", "") + (f":{hop['ref']}" if hop.get("ref") else "")
            for hop in self.path
        )


def _newest_grant_import(db: Session, node_id: int) -> int | None:
    newest, _ = _newest_import_ids(db, node_id, "aws_authorization_details")
    return newest


def for_identity(db: Session, identity: Identity) -> list[ObservedGrant]:
    newest = _newest_grant_import(db, identity.scope_node_id)
    if newest is None:
        return []
    node = db.get(ScopeNode, identity.scope_node_id)
    account = node.external_id if node else ""
    live = {
        authorizations.grant_key(row.path, row.role_definition_external_id)
        for row in authorizations.active(db, identity.id)
    }
    out: list[ObservedGrant] = []
    rows = db.execute(
        select(Grant, RoleDefinition)
        .join(RoleDefinition, Grant.role_definition_id == RoleDefinition.id)
        .where(Grant.import_id == newest, Grant.identity_id == identity.id)
        .order_by(RoleDefinition.display_name_last)
    ).all()
    for grant, definition in rows:
        out.append(_candidate(identity, account, definition, grant.mode,
                              grant.path, grant.source_kind, live))

    # Access that arrives through a group is still access the identity
    # holds, and leaving it out of the export would let a person fill
    # in a file, import it, and believe an estate authorized while a
    # whole class of privilege went unmentioned. The hop is recorded
    # rather than flattened, so the authorization says how it arrives.
    for group, grant, definition in _group_grants(db, identity, newest):
        out.append(_candidate(
            identity, account, definition, grant.mode,
            [{"via": "membership", "ref": group.first_display_name,
              "mode": "active"}],
            grant.source_kind, live,
        ))
    return out


def _candidate(
    identity: Identity,
    account: str,
    definition: RoleDefinition,
    mode: str,
    path: list[dict[str, str]],
    source_kind: str,
    live: set[str],
) -> ObservedGrant:
    key = authorizations.grant_key(path, definition.external_id)
    return ObservedGrant(
        identity_id=identity.id,
        identity_external_id=identity.external_id,
        display_name=identity.first_display_name,
        account=account,
        role_definition_external_id=definition.external_id,
        role_definition_hash=definition.contents_hash,
        role_display_name=definition.display_name_last,
        mode=mode,
        path=path,
        source_kind=source_kind,
        authorized=key in live,
    )


def _group_grants(
    db: Session, identity: Identity, import_id: int
) -> list[tuple[Identity, Grant, RoleDefinition]]:
    group_ids = list(db.execute(
        select(Membership.group_id).where(
            Membership.import_id == import_id,
            Membership.member_id == identity.id,
        )
    ).scalars())
    if not group_ids:
        return []
    rows = db.execute(
        select(Identity, Grant, RoleDefinition)
        .join(Grant, Grant.identity_id == Identity.id)
        .join(RoleDefinition, Grant.role_definition_id == RoleDefinition.id)
        .where(Grant.import_id == import_id, Identity.id.in_(group_ids))
        .order_by(Identity.first_display_name, RoleDefinition.display_name_last)
    ).all()
    return [(group, grant, definition) for group, grant, definition in rows]


def for_estate(db: Session) -> list[ObservedGrant]:
    """Every identity's observed grants, groups excluded: a group is a
    source of privilege and not an actor (D-019), and what a person
    authorizes is the identity's hold, however it arrives."""
    out: list[ObservedGrant] = []
    identities = db.execute(
        select(Identity)
        .where(Identity.kind != IdentityKind.group)
        .order_by(Identity.scope_node_id, Identity.first_display_name)
    ).scalars().all()
    for identity in identities:
        out.extend(for_identity(db, identity))
    return out


def export_csv(grants: list[ObservedGrant]) -> str:
    """The export shaped for the import: the shipped mapping's own
    columns, so the round trip is export, edit, import with nothing
    in between. The owner and the justification are left empty on
    purpose, because they are the two things the observed side cannot
    know and the two a person is being asked for."""
    from manifest_identity.decide.reports import csv_safe

    columns = [
        column
        for spec in csv_import.DEFAULT_FIELDS.values()
        if (column := spec.get("column")) is not None
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for grant in grants:
        writer.writerow({
            "identity_id": csv_safe(grant.identity_external_id),
            "role": csv_safe(grant.role_definition_external_id),
            "mode": csv_safe(grant.mode),
            "path": csv_safe(grant.path_text()),
            "owner_kind": "",
            "owner": "",
            "secondary_owner_kind": "",
            "secondary_owner": "",
            "justification": "",
            "reference": "",
            "control": "",
            "valid_from": "",
            "valid_until": "",
        })
    return buffer.getvalue()
