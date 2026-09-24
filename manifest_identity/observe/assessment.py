"""One assessment, many consumers.

The inventory list, the campaign builder, the exports, and the risk
report all answer from the same computation: derived state, credential
and privilege findings, and the governance adjustment. It lives here
once so a figure shown on the page, frozen into a campaign item, and
printed in a report cannot be three separately maintained versions of
the truth (the docs-truth lesson, applied to code paths).

This module is also where the neutral rows become what the privilege
reader expects: grants and role definitions become a policy index and
attachment lists, memberships become group facts, observed
relationships become trust policies. The provider's vocabulary ends
at the importer; the reader's vocabulary starts here.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from manifest_identity.authorize.governance import (
    EffectiveOwner,
    active_owners_by_target,
    apply_owner_governance,
    resolve_owner,
)
from manifest_identity.authorize.models import GovernanceRecord
from manifest_identity.core.models import ScopeNode
from manifest_identity.observe.derive import DerivedState, derive
from manifest_identity.observe.findings import Finding, evaluate
from manifest_identity.observe.models import (
    Credential,
    Grant,
    Identity,
    IdentityKind,
    IdentityObservation,
    Import,
    Membership,
    ObservedRelationship,
    RoleDefinition,
)
from manifest_identity.observe.privilege import (
    GroupFacts,
    PolicyIndex,
    PrivilegePicture,
    evaluate_group,
    evaluate_privilege,
    membership_drift,
    read_identity_privilege,
)


@dataclass
class AssessedIdentity:
    identity: Identity
    account: str
    observations: int
    state: DerivedState | None
    findings: list[Finding]
    picture: PrivilegePicture | None
    owner: EffectiveOwner | None
    flagged: bool
    name_reused: bool

    def tier_counts(self) -> dict[str, int]:
        tiers = {"critical": 0, "warning": 0, "notice": 0}
        for finding in self.findings:
            tiers[finding.tier] += 1
        return tiers


@dataclass
class AssessedGroup:
    group_id: int | None
    account: str
    name: str
    members: int
    privileged: bool
    findings: list[Finding]
    owner: EffectiveOwner | None
    flagged: bool
    records: list[GovernanceRecord]


@dataclass
class ScopeContext:
    """Everything the privilege reader needs for one scope node, read
    from the newest import that carries each kind of fact."""

    as_of: datetime
    index: PolicyIndex
    groups: dict[str, GroupFacts]
    previous_members: dict[str, list[str]]
    attached_by_identity: dict[int, list[dict[str, str]]]
    group_names_by_identity: dict[int, list[str]]
    trust_by_identity: dict[int, object]


def observation_pairs(
    db: Session, identity_ids: list[int]
) -> dict[int, list[tuple[IdentityObservation, datetime]]]:
    rows = db.execute(
        select(IdentityObservation, Import.captured_at)
        .join(Import, IdentityObservation.import_id == Import.id)
        .where(IdentityObservation.identity_id.in_(identity_ids))
    ).all()
    out: dict[int, list[tuple[IdentityObservation, datetime]]] = {}
    for obs, captured in rows:
        out.setdefault(obs.identity_id, []).append((obs, captured))
    return out


def credential_pairs(
    db: Session, identity_ids: list[int]
) -> dict[int, list[tuple[Credential, datetime]]]:
    rows = db.execute(
        select(Credential, Import.captured_at)
        .join(Import, Credential.import_id == Import.id)
        .where(Credential.identity_id.in_(identity_ids))
    ).all()
    out: dict[int, list[tuple[Credential, datetime]]] = {}
    for cred, captured in rows:
        out.setdefault(cred.identity_id, []).append((cred, captured))
    return out


def _newest_import_ids(
    db: Session, node_id: int, source_kind: str
) -> tuple[int | None, int | None]:
    """The newest and the previous import of one source kind for a
    scope, by capture time; membership drift compares the two."""
    rows = db.execute(
        select(Import.id)
        .where(Import.scope_node_id == node_id, Import.source_kind == source_kind)
        .order_by(Import.captured_at.desc(), Import.id.desc())
        .limit(2)
    ).scalars().all()
    newest = rows[0] if rows else None
    prior = rows[1] if len(rows) > 1 else None
    return newest, prior


def scope_context(db: Session, node_id: int) -> ScopeContext:
    as_of = db.execute(
        select(func.max(Import.captured_at)).where(Import.scope_node_id == node_id)
    ).scalar_one()
    newest, prior = _newest_import_ids(db, node_id, "aws_authorization_details")
    index = PolicyIndex()
    attached: dict[int, list[dict[str, str]]] = {}
    group_names: dict[int, list[str]] = {}
    trust: dict[int, object] = {}
    groups: dict[str, GroupFacts] = {}
    previous: dict[str, list[str]] = {}
    if newest is None:
        return ScopeContext(as_of, index, groups, previous, attached, group_names, trust)

    identities = {
        i.id: i for i in db.execute(
            select(Identity).where(Identity.scope_node_id == node_id)
        ).scalars()
    }
    grant_rows = db.execute(
        select(Grant, RoleDefinition)
        .join(RoleDefinition, Grant.role_definition_id == RoleDefinition.id)
        .where(Grant.import_id == newest)
    ).all()
    inline_by_owner: dict[int, list[str]] = {}
    for grant, definition in grant_rows:
        if grant.source_kind == "inline_policy":
            owner_key, _, name = definition.external_id[len("inline:"):].partition("#")
            index.inline.setdefault(owner_key, {})[name] = definition.contents
            inline_by_owner.setdefault(grant.identity_id, []).append(name)
        else:
            index.managed[definition.external_id] = definition.contents
            attached.setdefault(grant.identity_id, []).append(
                {"name": definition.display_name_last, "arn": definition.external_id}
            )
    for rel in db.execute(
        select(ObservedRelationship).where(
            ObservedRelationship.import_id == newest, ObservedRelationship.kind == "trust"
        )
    ).scalars():
        if rel.to_identity_id is not None:
            trust[rel.to_identity_id] = rel.document

    members_now: dict[int, list[str]] = {}
    for m in db.execute(select(Membership).where(Membership.import_id == newest)).scalars():
        member = identities.get(m.member_id)
        group = identities.get(m.group_id)
        if member is None or group is None:
            continue
        members_now.setdefault(m.group_id, []).append(member.external_id)
        group_names.setdefault(m.member_id, []).append(group.first_display_name)
    for group in identities.values():
        if group.kind != IdentityKind.group:
            continue
        name = _display_name(db, group.id, newest) or group.first_display_name
        groups[name] = GroupFacts(
            name=name,
            key=group.external_id,
            attached=list(attached.get(group.id, [])),
            inline_names=list(inline_by_owner.get(group.id, [])),
            members=list(members_now.get(group.id, [])),
        )
    if prior is not None:
        prior_members: dict[int, list[str]] = {}
        for m in db.execute(select(Membership).where(Membership.import_id == prior)).scalars():
            member = identities.get(m.member_id)
            if member is not None:
                prior_members.setdefault(m.group_id, []).append(member.external_id)
        for group_id, names in prior_members.items():
            group = identities.get(group_id)
            if group is not None:
                previous[_display_name(db, group_id, prior) or group.first_display_name] = names
    return ScopeContext(as_of, index, groups, previous, attached, group_names, trust)


def _display_name(db: Session, identity_id: int, import_id: int) -> str | None:
    return db.execute(
        select(IdentityObservation.display_name).where(
            IdentityObservation.identity_id == identity_id,
            IdentityObservation.import_id == import_id,
        )
    ).scalar_one_or_none()


def active_flag_targets(db: Session, target_type: str) -> set[int]:
    return {
        target_id
        for (target_id,) in db.execute(
            select(GovernanceRecord.target_id).where(
                GovernanceRecord.target_type == target_type,
                GovernanceRecord.kind == "flag",
                GovernanceRecord.cleared_at.is_(None),
            )
        ).all()
    }


def assess_identities(db: Session) -> list[AssessedIdentity]:
    rows = db.execute(
        select(Identity, ScopeNode.external_id)
        .join(ScopeNode, Identity.scope_node_id == ScopeNode.id)
        .where(Identity.kind != IdentityKind.group)
        .order_by(ScopeNode.external_id, Identity.first_display_name)
    ).all()
    pairs = observation_pairs(db, [i.id for i, _ in rows])
    creds = credential_pairs(db, [i.id for i, _ in rows])
    seen: dict[tuple[int, str], int] = {}
    for identity, _ in rows:
        key = (identity.scope_node_id, identity.first_display_name)
        seen[key] = seen.get(key, 0) + 1
    owners = active_owners_by_target(db, "identity")
    flagged = active_flag_targets(db, "identity")
    contexts: dict[int, ScopeContext] = {}
    out: list[AssessedIdentity] = []
    for identity, account in rows:
        mine = pairs.get(identity.id, [])
        state: DerivedState | None = None
        findings: list[Finding] = []
        picture: PrivilegePicture | None = None
        effective = resolve_owner(owners.get(identity.id), None)
        if mine:
            if identity.scope_node_id not in contexts:
                contexts[identity.scope_node_id] = scope_context(db, identity.scope_node_id)
            ctx = contexts[identity.scope_node_id]
            state = derive(mine, creds.get(identity.id, []), ctx.as_of)
            state.identity_type = identity.provider_type
            findings = evaluate(state)
            picture = read_identity_privilege(
                identity_key=identity.external_id,
                tags=state.tags,
                attached=ctx.attached_by_identity.get(identity.id) or None,
                group_names=ctx.group_names_by_identity.get(identity.id) or None,
                trust_policy=ctx.trust_by_identity.get(identity.id),
                account_id=account,
                index=ctx.index,
                groups=ctx.groups,
            )
            findings = findings + evaluate_privilege(picture)
            effective = resolve_owner(owners.get(identity.id), picture.owner)
            findings = apply_owner_governance(
                findings, effective, picture.owner, picture.combined.privileged
            )
        out.append(AssessedIdentity(
            identity=identity,
            account=account,
            observations=len(mine),
            state=state,
            findings=findings,
            picture=picture,
            owner=effective,
            flagged=identity.id in flagged,
            name_reused=(seen[(identity.scope_node_id, identity.first_display_name)] > 1),
        ))
    return out


def assess_groups(db: Session) -> list[AssessedGroup]:
    nodes = db.execute(
        select(ScopeNode).where(ScopeNode.kind == "account").order_by(ScopeNode.external_id)
    ).scalars().all()
    owners = active_owners_by_target(db, "group")
    out: list[AssessedGroup] = []
    for node in nodes:
        ctx = scope_context(db, node.id)
        ids = {
            g.external_id: g.id
            for g in db.execute(
                select(Identity).where(
                    Identity.scope_node_id == node.id, Identity.kind == IdentityKind.group
                )
            ).scalars()
        }
        for name, facts in sorted(ctx.groups.items()):
            reading, findings = evaluate_group(facts, ctx.index)
            if name in ctx.previous_members:
                findings = findings + membership_drift(
                    name, ctx.previous_members[name], facts.members
                )
            group_id = ids.get(facts.key)
            records = (
                list(db.execute(
                    select(GovernanceRecord)
                    .where(
                        GovernanceRecord.target_type == "group",
                        GovernanceRecord.target_id == group_id,
                    )
                    .order_by(GovernanceRecord.created_at.desc(), GovernanceRecord.id.desc())
                ).scalars())
                if group_id is not None
                else []
            )
            effective = resolve_owner(owners.get(group_id) if group_id is not None else None, None)
            findings = apply_owner_governance(findings, effective, None, reading.privileged)
            out.append(AssessedGroup(
                group_id=group_id,
                account=node.external_id,
                name=name,
                members=len(facts.members),
                privileged=reading.privileged,
                findings=findings,
                owner=effective,
                flagged=any(r.kind == "flag" and r.cleared_at is None for r in records),
                records=records,
            ))
    return out
