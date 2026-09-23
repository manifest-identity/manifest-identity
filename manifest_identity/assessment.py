"""One assessment, many consumers.

The inventory list, the campaign builder, the exports, and the risk
report all answer from the same computation: derived state, credential
and privilege findings, and the governance adjustment. It lives here
once so a figure shown on the page, frozen into a campaign item, and
printed in a report cannot be three separately maintained versions of
the truth (the docs-truth lesson, applied to code paths).
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from manifest_identity.derive import DerivedState, derive
from manifest_identity.findings import Finding, evaluate
from manifest_identity.governance import (
    EffectiveOwner,
    active_owners_by_target,
    apply_owner_governance,
    resolve_owner,
)
from manifest_identity.models import (
    Account,
    GovernanceRecord,
    Group,
    GroupObservation,
    Identity,
    Observation,
    PolicyDocumentRecord,
    Snapshot,
)
from manifest_identity.privilege import (
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


def observation_pairs(
    db: Session, identity_ids: list[int]
) -> dict[int, list[tuple[Observation, datetime]]]:
    rows = db.execute(
        select(Observation, Snapshot.captured_at)
        .join(Snapshot, Observation.snapshot_id == Snapshot.id)
        .where(Observation.identity_id.in_(identity_ids))
    ).all()
    out: dict[int, list[tuple[Observation, datetime]]] = {}
    for obs, captured in rows:
        out.setdefault(obs.identity_id, []).append((obs, captured))
    return out


def privilege_context(
    db: Session, account_id: int
) -> tuple[PolicyIndex, dict[str, GroupFacts], dict[str, list[str]]]:
    """Policies and groups from the freshest snapshot carrying each,
    the same read-time rule the derivation engine uses for fields, plus
    the previous membership for drift."""
    index = PolicyIndex()
    doc_rows = db.execute(
        select(PolicyDocumentRecord, Snapshot.captured_at)
        .join(Snapshot, PolicyDocumentRecord.snapshot_id == Snapshot.id)
        .where(Snapshot.account_id == account_id)
    ).all()
    if doc_rows:
        newest = max(captured for _, captured in doc_rows)
        for record, captured in doc_rows:
            if captured != newest:
                continue
            if record.policy_arn.startswith("inline:"):
                owner, _, name = record.policy_arn[len("inline:"):].partition("#")
                index.inline.setdefault(owner, {})[name] = record.document
            else:
                index.managed[record.policy_arn] = record.document

    group_rows = db.execute(
        select(GroupObservation, Group, Snapshot.captured_at)
        .join(Group, GroupObservation.group_id == Group.id)
        .join(Snapshot, GroupObservation.snapshot_id == Snapshot.id)
        .where(Snapshot.account_id == account_id)
        .order_by(Snapshot.captured_at)
    ).all()
    groups: dict[str, GroupFacts] = {}
    previous_members: dict[str, list[str]] = {}
    if group_rows:
        captures = sorted({captured for _, _, captured in group_rows})
        newest = captures[-1]
        prior = captures[-2] if len(captures) > 1 else None
        for observation, _group, captured in group_rows:  # noqa: B007
            if captured == newest:
                groups[observation.display_name] = GroupFacts(
                    name=observation.display_name,
                    key=_group.provider_identifier,
                    attached=list(observation.attached_policies or []),
                    inline_names=list(observation.inline_policy_names or []),
                    members=list(observation.member_identifiers or []),
                )
            elif prior is not None and captured == prior:
                previous_members[observation.display_name] = list(
                    observation.member_identifiers or []
                )
    return index, groups, previous_members


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
    identities = db.execute(
        select(Identity, Account.provider_account_id)
        .join(Account, Identity.account_id == Account.id)
        .order_by(Account.provider_account_id, Identity.first_display_name)
    ).all()
    as_of_by_account: dict[int, datetime] = dict(
        db.execute(
            select(Snapshot.account_id, func.max(Snapshot.captured_at))
            .group_by(Snapshot.account_id)
        ).tuples().all()
    )
    pairs = observation_pairs(db, [i.id for i, _ in identities])
    seen: dict[tuple[int, str], int] = {}
    for identity, _ in identities:
        key = (identity.account_id, identity.first_display_name)
        seen[key] = seen.get(key, 0) + 1
    owners = active_owners_by_target(db, "identity")
    flagged = active_flag_targets(db, "identity")
    contexts: dict[
        int, tuple[PolicyIndex, dict[str, GroupFacts], dict[str, list[str]]]
    ] = {}
    out: list[AssessedIdentity] = []
    for identity, account in identities:
        mine = pairs.get(identity.id, [])
        state: DerivedState | None = None
        findings: list[Finding] = []
        picture: PrivilegePicture | None = None
        effective = resolve_owner(owners.get(identity.id), None)
        if mine and identity.account_id in as_of_by_account:
            state = derive(mine, as_of_by_account[identity.account_id])
            state.identity_type = identity.identity_type
            findings = evaluate(state)
            if identity.account_id not in contexts:
                contexts[identity.account_id] = privilege_context(
                    db, identity.account_id
                )
            index, groups, _ = contexts[identity.account_id]
            picture = read_identity_privilege(
                identity_key=identity.provider_identifier,
                tags=state.tags,
                attached=state.attached_raw,
                group_names=state.group_names,
                trust_policy=state.trust_policy,
                account_id=account,
                index=index,
                groups=groups,
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
            name_reused=(
                seen[(identity.account_id, identity.first_display_name)] > 1
            ),
        ))
    return out


def assess_groups(db: Session) -> list[AssessedGroup]:
    accounts = db.execute(select(Account)).scalars().all()
    owners = active_owners_by_target(db, "group")
    out: list[AssessedGroup] = []
    for account in accounts:
        index, groups, previous = privilege_context(db, account.id)
        ids = {
            g.provider_identifier: g.id
            for g in db.execute(
                select(Group).where(Group.account_id == account.id)
            ).scalars()
        }
        for name, facts in sorted(groups.items()):
            reading, findings = evaluate_group(facts, index)
            if name in previous:
                findings = findings + membership_drift(
                    name, previous[name], facts.members
                )
            group_id = ids.get(facts.key)
            records = (
                list(
                    db.execute(
                        select(GovernanceRecord)
                        .where(
                            GovernanceRecord.target_type == "group",
                            GovernanceRecord.target_id == group_id,
                        )
                        .order_by(
                            GovernanceRecord.created_at.desc(),
                            GovernanceRecord.id.desc(),
                        )
                    ).scalars()
                )
                if group_id is not None
                else []
            )
            effective = resolve_owner(
                owners.get(group_id) if group_id is not None else None, None
            )
            findings = apply_owner_governance(
                findings, effective, None, reading.privileged
            )
            out.append(AssessedGroup(
                group_id=group_id,
                account=account.provider_account_id,
                name=name,
                members=len(facts.members),
                privileged=reading.privileged,
                findings=findings,
                owner=effective,
                flagged=any(
                    r.kind == "flag" and r.cleared_at is None for r in records
                ),
                records=records,
            ))
    return out
