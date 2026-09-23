"""The credential report importer: append-only, one transaction.

Everything one import creates, the account row if new, the snapshot,
any new identities, every observation, and the audit line, commits
together or not at all. Nothing is ever updated in place; a re-import
of the same capture is rejected by the snapshot's unique constraint,
and a new capture only adds rows (D-006).
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from manifest_identity import audit
from manifest_identity.ingest.authorization_details import ParsedDetails
from manifest_identity.ingest.credential_report import ParsedReport, provisional_key
from manifest_identity.models import (
    Account,
    Group,
    GroupObservation,
    Identity,
    Observation,
    PolicyDocumentRecord,
    Snapshot,
)

SOURCE = "credential_report"


class DuplicateSnapshot(ValueError):
    """This account, source, and capture time were already imported."""


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


def import_credential_report(
    db: Session,
    *,
    report: ParsedReport,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    if captured_at.tzinfo is None:
        raise CaptureTimeInvalid("capture time must carry a timezone")
    captured_at = captured_at.astimezone(UTC)
    if captured_at > datetime.now(UTC) + timedelta(minutes=5):
        raise CaptureTimeInvalid("capture time is in the future")

    account = db.execute(
        select(Account).where(Account.provider_account_id == report.account_id)
    ).scalar_one_or_none()
    if account is None:
        account = Account(
            provider_account_id=report.account_id,
            display_name=report.account_id,
        )
        db.add(account)
        db.flush()

    duplicate = db.execute(
        select(Snapshot).where(
            Snapshot.account_id == account.id,
            Snapshot.source == SOURCE,
            Snapshot.captured_at == captured_at,
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        db.rollback()
        raise DuplicateSnapshot(
            "this account, source, and capture time were already imported"
        )

    snapshot = Snapshot(
        account_id=account.id,
        source=SOURCE,
        captured_at=captured_at,
        source_filename=(source_filename or "")[:255] or None,
        row_count=len(report.rows),
        skipped_count=report.skipped,
    )
    db.add(snapshot)
    db.flush()

    existing = db.execute(
        select(Identity).where(Identity.account_id == account.id)
    ).scalars().all()
    known = {identity.provider_identifier: identity for identity in existing}
    # An identity upgraded to its real identifier keeps the key this
    # file can compute, so a later report finds it rather than minting
    # a duplicate beside it.
    by_provisional = {
        identity.provisional_key: identity
        for identity in existing
        if identity.provisional_key
    }
    new_count = 0
    seen_this_snapshot: set[str] = set()
    skipped = report.skipped
    observations = 0
    for row in report.rows:
        # A file repeating the same principal would violate the
        # one-observation-per-identity rule; the repeat is a skip.
        if row.provisional_key in seen_this_snapshot:
            skipped += 1
            continue
        seen_this_snapshot.add(row.provisional_key)
        identity = by_provisional.get(row.provisional_key) or known.get(
            row.provisional_key
        )
        if identity is None:
            identity = Identity(
                account_id=account.id,
                provider_identifier=row.provisional_key,
                provisional=True,
                provisional_key=row.provisional_key,
                identity_type="root" if row.is_root else "user",
                first_display_name=row.display_name,
            )
            db.add(identity)
            db.flush()
            known[row.provisional_key] = identity
            by_provisional[row.provisional_key] = identity
            new_count += 1
        db.add(
            Observation(
                snapshot_id=snapshot.id,
                identity_id=identity.id,
                display_name=row.display_name,
                arn=row.arn,
                identity_created_at=row.identity_created_at,
                password_enabled=row.password_enabled,
                password_last_used=row.password_last_used,
                password_last_changed=row.password_last_changed,
                mfa_active=row.mfa_active,
                key1_active=row.key1_active,
                key1_last_rotated=row.key1_last_rotated,
                key1_last_used=row.key1_last_used,
                key1_last_service=row.key1_last_service,
                key2_active=row.key2_active,
                key2_last_rotated=row.key2_last_rotated,
                key2_last_used=row.key2_last_used,
                key2_last_service=row.key2_last_service,
                cert1_active=row.cert1_active,
                cert2_active=row.cert2_active,
            )
        )
        observations += 1

    snapshot.skipped_count = skipped
    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"account {report.account_id}",
        detail=(
            f"source {SOURCE}, captured {captured_at.isoformat()}, "
            f"{observations} observations, {new_count} new identities, "
            f"{skipped} skipped"
        ),
    )
    try:
        db.commit()
    except IntegrityError as exc:
        # The unique constraint is the last word on duplicates.
        db.rollback()
        raise DuplicateSnapshot(
            "this account, source, and capture time were already imported"
        ) from exc

    return ImportResult(
        account=report.account_id,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=len(seen_this_snapshot) - new_count,
        observations=observations,
        skipped_rows=skipped,
    )


SOURCE_AUTHORIZATION = "authorization_details"


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
    if captured_at.tzinfo is None:
        raise CaptureTimeInvalid("capture time must carry a timezone")
    captured_at = captured_at.astimezone(UTC)
    if captured_at > datetime.now(UTC) + timedelta(minutes=5):
        raise CaptureTimeInvalid("capture time is in the future")

    account = db.execute(
        select(Account).where(Account.provider_account_id == report.account_id)
    ).scalar_one_or_none()
    if account is None:
        account = Account(
            provider_account_id=report.account_id,
            display_name=report.account_id,
        )
        db.add(account)
        db.flush()

    if db.execute(
        select(Snapshot).where(
            Snapshot.account_id == account.id,
            Snapshot.source == SOURCE_AUTHORIZATION,
            Snapshot.captured_at == captured_at,
        )
    ).scalar_one_or_none() is not None:
        db.rollback()
        raise DuplicateSnapshot(
            "this account, source, and capture time were already imported"
        )

    snapshot = Snapshot(
        account_id=account.id,
        source=SOURCE_AUTHORIZATION,
        captured_at=captured_at,
        source_filename=(source_filename or "")[:255] or None,
        row_count=len(report.users) + len(report.roles) + len(report.groups),
        skipped_count=report.skipped,
    )
    db.add(snapshot)
    db.flush()

    identities = {
        identity.provider_identifier: identity
        for identity in db.execute(
            select(Identity).where(Identity.account_id == account.id)
        ).scalars()
    }
    new_count = 0
    upgraded = 0
    observations = 0

    def get_or_create(
        real_id: str, name: str, arn: str, created: datetime | None, kind: str
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
            provisional.provider_identifier = real_id
            provisional.provisional = False
            provisional.provisional_key = pk
            identities.pop(pk)
            identities[real_id] = provisional
            upgraded += 1
            return provisional
        identity = Identity(
            account_id=account.id,
            provider_identifier=real_id,
            provisional=False,
            provisional_key=pk,
            identity_type=kind,
            first_display_name=name,
        )
        db.add(identity)
        db.flush()
        identities[real_id] = identity
        new_count += 1
        return identity

    for user in report.users:
        identity = get_or_create(
            user.user_id, user.name, user.arn, user.created, "user"
        )
        db.add(
            Observation(
                snapshot_id=snapshot.id,
                identity_id=identity.id,
                display_name=user.name,
                arn=user.arn,
                identity_created_at=user.created,
                tags=user.tags or None,
                attached_policies=user.attached_policies or None,
                inline_policy_names=user.inline_policy_names or None,
                group_names=user.group_names or None,
            )
        )
        observations += 1

    for role in report.roles:
        identity = get_or_create(
            role.role_id, role.name, role.arn, role.created, "role"
        )
        db.add(
            Observation(
                snapshot_id=snapshot.id,
                identity_id=identity.id,
                display_name=role.name,
                arn=role.arn,
                identity_created_at=role.created,
                role_last_used=role.last_used,
                role_last_used_region=role.last_used_region,
                trust_policy=role.trust_policy,
                tags=role.tags or None,
                attached_policies=role.attached_policies or None,
                inline_policy_names=role.inline_policy_names or None,
            )
        )
        observations += 1

    name_to_user_ids: dict[str, list[str]] = {}
    for user in report.users:
        for group_name in user.group_names:
            name_to_user_ids.setdefault(group_name, []).append(user.user_id)

    groups = {
        group.provider_identifier: group
        for group in db.execute(
            select(Group).where(Group.account_id == account.id)
        ).scalars()
    }
    for parsed_group in report.groups:
        group = groups.get(parsed_group.group_id)
        if group is None:
            group = Group(
                account_id=account.id,
                provider_identifier=parsed_group.group_id,
                display_name=parsed_group.name,
            )
            db.add(group)
            db.flush()
            groups[parsed_group.group_id] = group
        db.add(
            GroupObservation(
                snapshot_id=snapshot.id,
                group_id=group.id,
                display_name=parsed_group.name,
                arn=parsed_group.arn,
                attached_policies=parsed_group.attached_policies or None,
                inline_policy_names=parsed_group.inline_policy_names or None,
                member_identifiers=name_to_user_ids.get(parsed_group.name) or None,
            )
        )

    for policy in report.policies:
        db.add(
            PolicyDocumentRecord(
                snapshot_id=snapshot.id,
                policy_arn=policy.arn,
                policy_name=policy.name,
                aws_managed=policy.aws_managed,
                document=policy.document,
            )
        )

    # Inline documents are stored under a synthetic identifier naming
    # their owner by the provider's immutable identifier, never by ARN
    # (D-016): during a resurrection window two identities share an ARN,
    # and attributing one's inline policies to the other would hand a
    # dead identity the live one's privilege.
    for owner_key, inline in (
        [(u.user_id, u.inline_documents) for u in report.users]
        + [(r.role_id, r.inline_documents) for r in report.roles]
        + [(g.group_id, g.inline_documents) for g in report.groups]
    ):
        for entry in inline:
            db.add(
                PolicyDocumentRecord(
                    snapshot_id=snapshot.id,
                    policy_arn=f"inline:{owner_key}#{entry['name']}"[:2048],
                    policy_name=str(entry["name"]),
                    aws_managed=False,
                    document=entry["document"],
                )
            )

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
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateSnapshot(
            "this account, source, and capture time were already imported"
        ) from exc

    return ImportResult(
        account=report.account_id,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=upgraded,
        observations=observations,
        skipped_rows=report.skipped,
    )
