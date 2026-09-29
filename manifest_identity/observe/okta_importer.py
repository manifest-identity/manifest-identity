"""The Okta importer: the sixth provider on the neutral tables.

The provider's vocabulary becomes the neutral one here and nowhere
else, under the transaction discipline the other importers keep.

What each thing becomes:

- The organization is a scope node of kind organization, keyed by its
  identifier and shown by its subdomain, with no partition to name.
- A user is an identity keyed by its identifier. One whose credentials
  come from Okta itself has a password credential, active while the
  account is in a status it can be signed into; one whose credentials
  come from a directory, a federation, or a social provider signs in
  elsewhere and has no password here. The second factor state is
  whether any factor is enrolled, when the export joined the factors
  in; activity is the last login. A deprovisioned user keeps its rows
  with the credential inactive.
- A group is an identity of kind group with a membership row per
  member, the built-in everyone group included.
- An administrator role is a provider-managed definition keyed by its
  type, whose contents are a capability document from a table of what
  each type may do: the super administrator administers; the roles
  that manage users, groups, credentials, or other roles change
  access; the application and mobile administrators write; the
  read-only and report administrators read. A custom role is a
  customer-managed definition read from its permissions when the
  export carries them, with the permissions riding as actions.
- A role assignment is one grant at the organization: on a user when
  assigned to the user, on the group when assigned to a group, so the
  membership hop carries it to the members with the group's name kept.
- An application is a definition of its own, customer managed, that
  reads and nothing more; an assignment of it is a grant, on the user
  or the group, so every application a person can open is something
  somebody can be asked to authorize.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.models import Partition, Provider, ScopeNode
from manifest_identity.core.scope import find_or_create_node
from manifest_identity.observe.importer import (
    ImportResult,
    _check_capture,
    _commit_or_duplicate,
    _new_import,
    role_definition_for,
)
from manifest_identity.observe.models import (
    Credential,
    CredentialKind,
    Grant,
    GrantMode,
    Identity,
    IdentityKind,
    IdentityObservation,
    Membership,
    ProviderInstance,
    RoleDefinition,
)
from manifest_identity.observe.policy_analysis import capability_document
from manifest_identity.observe.providers.okta.org_export import (
    LIVE_STATUSES,
    ParsedCustomRole,
    ParsedOrg,
)

SOURCE_ORG = "okta_org"

# Each entry is administers, changes access, writes, reads, in that order.
ROLE_TABLE: dict[str, tuple[bool, bool, bool, bool]] = {
    "SUPER_ADMIN": (True, True, True, True),
    "ORG_ADMIN": (False, True, True, True),
    "USER_ADMIN": (False, True, True, True),
    "GROUP_ADMIN": (False, True, True, True),
    "GROUP_MEMBERSHIP_ADMIN": (False, True, True, True),
    "HELP_DESK_ADMIN": (False, True, False, True),
    "APP_ADMIN": (False, False, True, True),
    "MOBILE_ADMIN": (False, False, True, True),
    "API_ACCESS_MANAGEMENT_ADMIN": (False, False, True, True),
    "API_ADMIN": (False, False, True, True),
    "READ_ONLY_ADMIN": (False, False, False, True),
    "REPORT_ADMIN": (False, False, False, True),
}
ACCESS_PERMISSION_PREFIXES = (
    "okta.users.manage", "okta.users.credentials", "okta.users.lifecycle",
    "okta.users.userprofile.manage", "okta.groups.manage", "okta.groups.members.manage",
    "okta.groups.create", "okta.users.create", "okta.iam.", "okta.apps.assignment.manage",
)

DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def role_capabilities(role_type: str, label: str) -> dict[str, object]:
    administers, changes_access, writes, reads = ROLE_TABLE.get(
        role_type, (False, False, False, False)
    )
    return capability_document(
        "okta", label, "organization", administers=administers, changes_access=changes_access,
        writes=writes, reads=reads,
    )


def custom_role_capabilities(role: ParsedCustomRole) -> dict[str, object]:
    changes_access = any(p.startswith(ACCESS_PERMISSION_PREFIXES) for p in role.permissions)
    writes = changes_access or any(
        p.endswith((".manage", ".create", ".delete", ".update")) for p in role.permissions
    )
    reads = writes or any(p.endswith(".read") for p in role.permissions)
    return capability_document(
        "okta", role.label, "organization", administers=False, changes_access=changes_access,
        writes=writes, reads=reads, actions=role.permissions,
    )


def org_scope(db: Session, org_id: str, subdomain: str) -> tuple[ProviderInstance, ScopeNode]:
    node = find_or_create_node(
        db, Provider.okta, Partition.none, "organization", org_id, subdomain, None
    )
    provider = db.execute(
        select(ProviderInstance).where(
            ProviderInstance.provider == Provider.okta.value,
            ProviderInstance.root_scope_node_id == node.id,
        )
    ).scalar_one_or_none()
    if provider is None:
        provider = ProviderInstance(
            provider=Provider.okta.value, display_name=subdomain, root_scope_node_id=node.id,
        )
        db.add(provider)
        db.flush()
    return provider, node


def org_node_id(db: Session, org_id: str) -> int | None:
    return db.execute(
        select(ScopeNode.id).where(
            ScopeNode.provider == Provider.okta.value,
            ScopeNode.kind == "organization",
            ScopeNode.external_id == org_id,
        )
    ).scalar()


def import_org_export(
    db: Session,
    *,
    export: ParsedOrg,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    provider, node = org_scope(db, export.id, export.subdomain)
    import_row = _new_import(
        db, provider, node, SOURCE_ORG, captured_at, source_filename, actor_username,
        len(export.users) + len(export.groups) + len(export.role_assignments)
        + sum(len(a.assignments) for a in export.apps),
        export.skipped,
    )

    identities = {
        identity.external_id: identity
        for identity in db.execute(
            select(Identity).where(Identity.scope_node_id == node.id)
        ).scalars()
    }
    new_count = 0
    observations = 0
    definitions: dict[tuple[str, str], RoleDefinition] = {}

    def get_or_create(
        external_id: str, name: str, provider_type: str, kind: IdentityKind,
    ) -> Identity:
        nonlocal new_count
        identity = identities.get(external_id)
        if identity is None:
            identity = Identity(
                provider_id=provider.id, scope_node_id=node.id, external_id=external_id,
                provider_type=provider_type, kind=kind, first_display_name=name[:255],
                provisional=False,
            )
            db.add(identity)
            db.flush()
            identities[external_id] = identity
            new_count += 1
        return identity

    by_id: dict[str, Identity] = {}
    for user in export.users:
        identity = get_or_create(f"user:{user.id}", user.login, "user", IdentityKind.unknown)
        by_id[user.id] = identity
        live = user.status in LIVE_STATUSES
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id, display_name=user.login[:255],
            provider_ref=user.login[:2048], identity_created_at=user.created,
            mfa_active=None if user.factors is None else bool(user.factors),
            last_activity=user.last_login,
            raw={"status": user.status, "provider": user.provider_type,
                 "factors": user.factors},
        ))
        observations += 1
        # A password lives here only when Okta holds it; a directory or
        # a federation holds the others.
        if user.provider_type == "OKTA":
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id,
                kind=CredentialKind.password, external_id="sign-in", active=live,
                last_rotated=user.password_changed, last_used=user.last_login,
            ))

    for group in export.groups:
        identity = get_or_create(f"group:{group.id}", group.name, "group", IdentityKind.group)
        by_id[group.id] = identity
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id, display_name=group.name[:255],
            provider_ref=group.id, raw={"type": group.kind},
        ))
        observations += 1
        for member_id in group.member_ids:
            member = by_id.get(member_id)
            if member is not None:
                db.add(Membership(
                    import_id=import_row.id, member_id=member.id, group_id=identity.id,
                    mode="active",
                ))

    custom = {r.id: r for r in export.custom_roles}

    def definition_for(row_type: str, label: str, custom_id: str | None) -> RoleDefinition:
        if row_type == "CUSTOM" and custom_id is not None:
            described = custom.get(custom_id)
            document = (
                custom_role_capabilities(described) if described is not None
                else capability_document(
                    "okta", label, "organization", administers=False,
                    changes_access=False, writes=False, reads=False,
                )
            )
            return role_definition_for(
                db, provider, f"okta:role:custom:{custom_id}",
                described.label if described is not None else label, "customer", document,
                import_row, definitions,
            )
        return role_definition_for(
            db, provider, f"okta:role:{row_type}", label, "provider",
            role_capabilities(row_type, label), import_row, definitions,
        )

    for row in export.role_assignments:
        if not row.active:
            continue
        definition = definition_for(row.role_type, row.label, row.custom_role_id)
        db.add(Grant(
            import_id=import_row.id, identity_id=by_id[row.principal_id].id,
            role_definition_id=definition.id, scope_node_id=node.id,
            mode=GrantMode.standing, path=list(DIRECT),
            source_kind="role_assignment", source_ref=row.id,
        ))

    app_grants = 0
    for app in export.apps:
        if not app.active:
            continue
        definition = role_definition_for(
            db, provider, f"okta:app:{app.id}", app.label, "customer",
            capability_document(
                "okta", app.label, "application", administers=False, changes_access=False,
                writes=False, reads=True,
            ),
            import_row, definitions,
        )
        for assignment in app.assignments:
            db.add(Grant(
                import_id=import_row.id, identity_id=by_id[assignment.principal_id].id,
                role_definition_id=definition.id, scope_node_id=node.id,
                mode=GrantMode.standing, path=list(DIRECT),
                source_kind="app_assignment", source_ref=app.id,
            ))
            app_grants += 1

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"organization {export.subdomain}",
        detail=(
            f"source {SOURCE_ORG}, captured {captured_at.isoformat()}, "
            f"{observations} observations, {new_count} new identities, "
            f"{len(export.role_assignments)} role assignments, {len(export.apps)} apps, "
            f"{app_grants} app assignments"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=export.subdomain,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=0,
        observations=observations,
        skipped_rows=export.skipped,
    )
