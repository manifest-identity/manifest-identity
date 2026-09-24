"""The AWS importers: append-only, one transaction each.

Everything one import creates, the scope nodes if new, the import row,
any new identities, every observation, credential, grant, membership,
and relationship, and the audit line, commits together or not at all.
Nothing is ever updated in place; a re-import of the same capture is
rejected by the import row's unique constraint, and a new capture only
adds rows (D-006).

The AWS vocabulary becomes the neutral one here and nowhere else: the
credential report's two key slots become credential rows, the
authorization details file's policies become versioned role
definitions, its attachments become grants, its groups become
identities of kind group with membership rows, and its trust policies
become observed relationships.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.models import Partition, Provider, ScopeNode
from manifest_identity.core.scope import find_or_create_node
from manifest_identity.observe.models import (
    Credential,
    CredentialKind,
    Grant,
    GrantMode,
    Identity,
    IdentityKind,
    IdentityObservation,
    Import,
    Membership,
    ObservedRelationship,
    ProviderInstance,
    RoleDefinition,
)
from manifest_identity.observe.providers.aws.authorization_details import ParsedDetails
from manifest_identity.observe.providers.aws.credential_report import (
    ParsedReport,
    provisional_key,
)

SOURCE_CREDENTIAL_REPORT = "aws_credential_report"
SOURCE_AUTHORIZATION = "aws_authorization_details"


class DuplicateSnapshot(ValueError):
    """This scope, source, and capture time were already imported."""


class CaptureTimeInvalid(ValueError):
    """States the rule; never echoes the value."""


@dataclass
class ImportResult:
    account: str
    captured_at: datetime
    identities_new: int
    identities_known: int
    observations: int
    skipped_rows: int


def _check_capture(captured_at: datetime) -> datetime:
    if captured_at.tzinfo is None:
        raise CaptureTimeInvalid("capture time must carry a timezone")
    captured_at = captured_at.astimezone(UTC)
    if captured_at > datetime.now(UTC) + timedelta(minutes=5):
        raise CaptureTimeInvalid("capture time is in the future")
    return captured_at


def partition_from_arn(arn: str | None) -> Partition:
    """The partition is read from the file's own ARNs, never assumed:
    arn:aws-us-gov: is GovCloud, arn:aws: is commercial."""
    if arn and arn.startswith("arn:aws-us-gov:"):
        return Partition.aws_govcloud_us
    return Partition.aws_commercial


def aws_account_scope(
    db: Session, account_id: str, partition: Partition
) -> tuple[ProviderInstance, ScopeNode]:
    """The partition node, the account node beneath it, and the AWS
    provider row that names the partition node as its root."""
    partition_node = find_or_create_node(
        db, Provider.aws, partition, "partition", partition.value,
        "AWS GovCloud (US)" if partition == Partition.aws_govcloud_us else "AWS Commercial",
        None,
    )
    account_node = find_or_create_node(
        db, Provider.aws, partition, "account", account_id, account_id, partition_node
    )
    provider = db.execute(
        select(ProviderInstance).where(
            ProviderInstance.provider == Provider.aws.value,
            ProviderInstance.root_scope_node_id == partition_node.id,
        )
    ).scalar_one_or_none()
    if provider is None:
        provider = ProviderInstance(
            provider=Provider.aws.value,
            display_name=partition_node.display_name,
            root_scope_node_id=partition_node.id,
        )
        db.add(provider)
        db.flush()
    return provider, account_node


def _new_import(
    db: Session,
    provider: ProviderInstance,
    node: ScopeNode,
    source_kind: str,
    captured_at: datetime,
    source_filename: str | None,
    actor_username: str,
    row_count: int,
    skipped: int,
) -> Import:
    if db.execute(
        select(Import).where(
            Import.scope_node_id == node.id,
            Import.source_kind == source_kind,
            Import.captured_at == captured_at,
        )
    ).scalar_one_or_none() is not None:
        db.rollback()
        raise DuplicateSnapshot(
            "this account, source, and capture time were already imported"
        )
    row = Import(
        provider_id=provider.id,
        scope_node_id=node.id,
        source_kind=source_kind,
        captured_at=captured_at,
        imported_by_username=actor_username,
        source_filename=(source_filename or "")[:255] or None,
        row_count=row_count,
        skipped_count=skipped,
    )
    db.add(row)
    db.flush()
    return row


def _commit_or_duplicate(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        # The unique constraint is the last word on duplicates.
        db.rollback()
        raise DuplicateSnapshot(
            "this account, source, and capture time were already imported"
        ) from exc


def contents_hash(document: object) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def role_definition_for(
    db: Session,
    provider: ProviderInstance,
    external_id: str,
    name: str,
    managed_by: str,
    document: object,
    import_row: Import,
    cache: dict[tuple[str, str], RoleDefinition],
) -> RoleDefinition:
    """A definition is keyed by its stable id and the hash of its
    contents; a changed policy is a new row, and the last-seen import
    moves forward on an unchanged one."""
    digest = contents_hash(document)
    key = (external_id[:2048], digest)
    if key in cache:
        return cache[key]
    definition = db.execute(
        select(RoleDefinition).where(
            RoleDefinition.provider_id == provider.id,
            RoleDefinition.external_id == external_id[:2048],
            RoleDefinition.contents_hash == digest,
        )
    ).scalar_one_or_none()
    if definition is None:
        definition = RoleDefinition(
            provider_id=provider.id,
            external_id=external_id[:2048],
            display_name_last=name[:255],
            managed_by=managed_by,
            contents_hash=digest,
            contents=document if isinstance(document, dict) else None,
            first_seen_import_id=import_row.id,
            last_seen_import_id=import_row.id,
        )
        db.add(definition)
        db.flush()
    else:
        definition.last_seen_import_id = import_row.id
        definition.display_name_last = name[:255]
    cache[key] = definition
    return definition


def import_credential_report(
    db: Session,
    *,
    report: ParsedReport,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    partition = partition_from_arn(next((r.arn for r in report.rows if r.arn), None))
    provider, node = aws_account_scope(db, report.account_id, partition)
    import_row = _new_import(
        db, provider, node, SOURCE_CREDENTIAL_REPORT, captured_at, source_filename,
        actor_username, len(report.rows), report.skipped,
    )

    existing = db.execute(
        select(Identity).where(Identity.scope_node_id == node.id)
    ).scalars().all()
    known = {identity.external_id: identity for identity in existing}
    # An identity upgraded to its real identifier keeps the key this
    # file can compute, so a later report finds it rather than minting
    # a duplicate beside it.
    by_provisional = {
        identity.provisional_key: identity
        for identity in existing
        if identity.provisional_key
    }
    new_count = 0
    seen: set[str] = set()
    skipped = report.skipped
    observations = 0
    for row in report.rows:
        # A file repeating the same principal would violate the
        # one-observation-per-identity rule; the repeat is a skip.
        if row.provisional_key in seen:
            skipped += 1
            continue
        seen.add(row.provisional_key)
        identity = by_provisional.get(row.provisional_key) or known.get(row.provisional_key)
        if identity is None:
            identity = Identity(
                provider_id=provider.id,
                scope_node_id=node.id,
                external_id=row.provisional_key,
                provider_type="root" if row.is_root else "user",
                kind=IdentityKind.person if row.is_root else IdentityKind.unknown,
                first_display_name=row.display_name,
                provisional=True,
                provisional_key=row.provisional_key,
            )
            db.add(identity)
            db.flush()
            known[row.provisional_key] = identity
            by_provisional[row.provisional_key] = identity
            new_count += 1
        activity = [
            t for t in (row.password_last_used, row.key1_last_used, row.key2_last_used)
            if isinstance(t, datetime)
        ]
        db.add(
            IdentityObservation(
                import_id=import_row.id,
                identity_id=identity.id,
                display_name=row.display_name,
                provider_ref=row.arn,
                identity_created_at=row.identity_created_at,
                mfa_active=row.mfa_active,
                last_activity=max(activity) if activity else None,
                last_activity_detail="credential report",
            )
        )
        if row.password_enabled is not None:
            db.add(
                Credential(
                    import_id=import_row.id,
                    identity_id=identity.id,
                    kind=CredentialKind.password,
                    external_id="console",
                    active=bool(row.password_enabled),
                    last_rotated=row.password_last_changed,
                    last_used=row.password_last_used,
                )
            )
        for label, active, rotated, used, service in (
            (
                "first", row.key1_active, row.key1_last_rotated,
                row.key1_last_used, row.key1_last_service,
            ),
            (
                "second", row.key2_active, row.key2_last_rotated,
                row.key2_last_used, row.key2_last_service,
            ),
        ):
            if active is None:
                continue
            db.add(
                Credential(
                    import_id=import_row.id,
                    identity_id=identity.id,
                    kind=CredentialKind.access_key,
                    external_id=label,
                    active=bool(active),
                    last_rotated=rotated,
                    last_used=used,
                    last_used_service=service,
                )
            )
        for label, active in (("first", row.cert1_active), ("second", row.cert2_active)):
            if active is None:
                continue
            db.add(
                Credential(
                    import_id=import_row.id,
                    identity_id=identity.id,
                    kind=CredentialKind.certificate,
                    external_id=label,
                    active=bool(active),
                )
            )
        observations += 1

    import_row.skipped_count = skipped
    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"account {report.account_id}",
        detail=(
            f"source {SOURCE_CREDENTIAL_REPORT}, captured {captured_at.isoformat()}, "
            f"{observations} observations, {new_count} new identities, "
            f"{skipped} skipped"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=report.account_id,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=len(seen) - new_count,
        observations=observations,
        skipped_rows=skipped,
    )


def import_authorization_details(
    db: Session,
    *,
    report: ParsedDetails,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    """Same transaction discipline as the credential report, plus the
    D-029 upgrade: a provisional identity whose immutable pair matches
    a user here is promoted to the real provider identifier."""
    captured_at = _check_capture(captured_at)
    first_arn = next(
        (x.arn for x in list(report.users) + list(report.roles) + list(report.groups)),
        None,
    )
    provider, node = aws_account_scope(db, report.account_id, partition_from_arn(first_arn))
    import_row = _new_import(
        db, provider, node, SOURCE_AUTHORIZATION, captured_at, source_filename,
        actor_username, len(report.users) + len(report.roles) + len(report.groups),
        report.skipped,
    )

    identities = {
        identity.external_id: identity
        for identity in db.execute(
            select(Identity).where(Identity.scope_node_id == node.id)
        ).scalars()
    }
    new_count = 0
    upgraded = 0
    observations = 0
    definitions: dict[tuple[str, str], RoleDefinition] = {}

    def get_or_create(
        real_id: str, name: str, arn: str, created: datetime | None,
        provider_type: str, kind: IdentityKind,
    ) -> Identity:
        nonlocal new_count, upgraded
        identity = identities.get(real_id)
        if identity is not None:
            return identity
        # The D-029 upgrade path: the credential report knew this
        # principal only by its immutable pair; promote in place.
        pk = provisional_key(arn, created)
        provisional = identities.get(pk)
        if provisional is not None and provisional.provisional:
            provisional.external_id = real_id
            provisional.provisional = False
            provisional.provisional_key = pk
            identities.pop(pk)
            identities[real_id] = provisional
            upgraded += 1
            return provisional
        identity = Identity(
            provider_id=provider.id,
            scope_node_id=node.id,
            external_id=real_id,
            provider_type=provider_type,
            kind=kind,
            first_display_name=name,
            provisional=False,
            provisional_key=pk,
        )
        db.add(identity)
        db.flush()
        identities[real_id] = identity
        new_count += 1
        return identity

    # Managed policies first, so attachments can point at them.
    for policy in report.policies:
        role_definition_for(
            db, provider, policy.arn, policy.name,
            "provider" if policy.aws_managed else "customer",
            policy.document, import_row, definitions,
        )

    def add_grants(
        identity: Identity, owner_key: str,
        attached: list[dict[str, str]], inline: list[dict[str, object]],
    ) -> None:
        for entry in attached:
            # The parser normalizes the file's PolicyArn and PolicyName
            # to arn and name; a row without an arn is not a grant.
            arn = str(entry.get("arn") or "")
            if not arn:
                continue
            name = str(entry.get("name") or arn)
            known = next((d for (eid, _), d in definitions.items() if eid == arn[:2048]), None)
            definition = known or role_definition_for(
                db, provider, arn, name,
                "provider" if ":aws:policy/" in arn or ":aws-us-gov:policy/" in arn else "customer",
                None, import_row, definitions,
            )
            db.add(Grant(
                import_id=import_row.id, identity_id=identity.id,
                role_definition_id=definition.id, scope_node_id=node.id,
                mode=GrantMode.standing, path=[{"via": "direct", "ref": "", "mode": "active"}],
                source_kind="attachment", source_ref=arn[:2048],
            ))
        # Inline documents are keyed by their owner's immutable
        # identifier, never by ARN (D-016): during a resurrection window
        # two identities share an ARN, and attributing one's inline
        # policies to the other would hand a dead identity the live
        # one's privilege.
        for document in inline:
            name = str(document["name"])
            definition = role_definition_for(
                db, provider, f"inline:{owner_key}#{name}", name, "customer",
                document.get("document"), import_row, definitions,
            )
            db.add(Grant(
                import_id=import_row.id, identity_id=identity.id,
                role_definition_id=definition.id, scope_node_id=node.id,
                mode=GrantMode.standing, path=[{"via": "direct", "ref": "", "mode": "active"}],
                source_kind="inline_policy", source_ref=name[:2048],
            ))

    for user in report.users:
        identity = get_or_create(
            user.user_id, user.name, user.arn, user.created, "user", IdentityKind.unknown
        )
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id,
            display_name=user.name, provider_ref=user.arn,
            identity_created_at=user.created, tags=user.tags or None,
        ))
        add_grants(identity, user.user_id, user.attached_policies, user.inline_documents)
        observations += 1

    for role in report.roles:
        identity = get_or_create(
            role.role_id, role.name, role.arn, role.created, "role", IdentityKind.service
        )
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id,
            display_name=role.name, provider_ref=role.arn,
            identity_created_at=role.created, tags=role.tags or None,
            last_activity=role.last_used,
            last_activity_detail=role.last_used_region,
        ))
        add_grants(identity, role.role_id, role.attached_policies, role.inline_documents)
        if role.trust_policy is not None:
            db.add(ObservedRelationship(
                import_id=import_row.id, kind="trust", to_identity_id=identity.id,
                from_ref="trust policy", from_kind="principal", document=role.trust_policy,
            ))
        observations += 1

    group_by_name: dict[str, Identity] = {}
    for parsed_group in report.groups:
        group = get_or_create(
            parsed_group.group_id, parsed_group.name, parsed_group.arn, None,
            "group", IdentityKind.group,
        )
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=group.id,
            display_name=parsed_group.name, provider_ref=parsed_group.arn,
        ))
        add_grants(
            group, parsed_group.group_id, parsed_group.attached_policies,
            parsed_group.inline_documents,
        )
        group_by_name[parsed_group.name] = group

    for user in report.users:
        member = identities.get(user.user_id)
        if member is None:
            continue
        for group_name in user.group_names:
            target = group_by_name.get(group_name)
            if target is None:
                continue
            db.add(Membership(
                import_id=import_row.id, member_id=member.id, group_id=target.id,
                mode="active",
            ))

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"account {report.account_id}",
        detail=(
            f"source {SOURCE_AUTHORIZATION}, captured {captured_at.isoformat()}, "
            f"{observations} observations, {new_count} new identities, "
            f"{upgraded} upgraded from provisional, {len(report.groups)} groups, "
            f"{len(report.policies)} policy documents, {report.skipped} skipped"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=report.account_id,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=upgraded,
        observations=observations,
        skipped_rows=report.skipped,
    )
