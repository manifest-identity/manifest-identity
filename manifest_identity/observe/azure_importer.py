"""The Azure and Entra importer: the fifth provider on the neutral tables.

The provider's vocabulary becomes the neutral one here and nowhere
else, under the transaction discipline the other importers keep.

What each thing becomes:

- The tenant is a scope node of kind tenant under the commercial or
  the government partition, whichever cloud the collector ran against;
  each subscription is a node beneath it, and each resource group an
  assignment names is a node beneath its subscription. An assignment
  deeper than a resource group is recorded at the resource group with
  its full scope in the grant's source reference.
- A member user is an identity with a password credential, because a
  directory account signs in, and the second factor state is the
  registration report's answer when the export carries it; activity is
  the last sign-in. A disabled account keeps its rows with the
  credential inactive. A guest is an identity from another tenant.
- A service principal is an identity of kind service (an application)
  or workload (a managed identity), keyed by its object id; each
  password credential is a client_secret and each key credential a
  certificate, with their validity windows, so an expired secret reads
  as inactive and a live one as held.
- A group is an identity of kind group with a membership row per
  member, and a group inside a group passes its members up, so the hop
  reads without a second mechanism.
- A directory role is a provider-managed definition keyed by its
  template identifier, whose contents are a capability document read
  from the role's published name: Global Administrator administers;
  the roles that manage users, groups, applications, credentials, or
  other roles change access; any other administrator writes; a reader
  reads. A member of the role holds it standing; a PIM eligibility is
  the same grant in the eligible mode, which is the can-obtain half
  the model has carried since 1.6.
- An Azure role is a definition keyed by its definition identifier,
  provider managed unless the export's role definitions call it
  custom, whose contents are read from its actions when listed (a
  wildcard administers; writing role assignments or the authorization
  namespace changes access) and from its name otherwise (Owner
  administers, User Access Administrator changes access, a
  contributor writes, a reader reads). An assignment is one grant at
  the subscription or resource group node.
- An assignment to a principal the directory lists is a grant on that
  identity; to one it does not, a guest with origin unresolved, so an
  assignment left behind by a deleted principal shows in the delta.
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
    Home,
    Identity,
    IdentityKind,
    IdentityObservation,
    Membership,
    ProviderInstance,
    RoleDefinition,
)
from manifest_identity.observe.policy_analysis import capability_document
from manifest_identity.observe.providers.azure.tenant_export import (
    ParsedMember,
    ParsedRoleDefinition,
    ParsedTenant,
)

SOURCE_TENANT = "azure_tenant"

# Directory roles by their published names. The one that administers
# the directory; the ones that change who holds what or what they sign
# in with; everything else is read from the words in its name.
DIRECTORY_ADMINISTERS = frozenset({"Global Administrator"})
DIRECTORY_CHANGES_ACCESS = frozenset({
    "Privileged Role Administrator", "Privileged Authentication Administrator",
    "User Administrator", "Groups Administrator", "Application Administrator",
    "Cloud Application Administrator", "Authentication Administrator",
    "Helpdesk Administrator", "Password Administrator", "Hybrid Identity Administrator",
    "Directory Writers", "Partner Tier1 Support", "Partner Tier2 Support",
    "Identity Governance Administrator", "Conditional Access Administrator",
})
# Azure roles by their published names, the same way.
AZURE_ADMINISTERS = frozenset({"Owner"})
AZURE_CHANGES_ACCESS = frozenset({
    "User Access Administrator", "Role Based Access Control Administrator",
})
AUTHORIZATION_ACTIONS = ("Microsoft.Authorization/roleAssignments/write",
                         "Microsoft.Authorization/*", "Microsoft.Authorization/*/write")

DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def directory_role_capabilities(name: str, template_id: str) -> dict[str, object]:
    administers = name in DIRECTORY_ADMINISTERS
    changes_access = administers or name in DIRECTORY_CHANGES_ACCESS
    writes = changes_access or "Administrator" in name or "Writer" in name
    reads = writes or "Reader" in name
    return capability_document(
        "azure", name, "tenant", administers=administers, changes_access=changes_access,
        writes=writes, reads=reads,
    )


def azure_role_capabilities(
    name: str, definition: ParsedRoleDefinition | None,
) -> dict[str, object]:
    if definition is not None and definition.actions:
        actions = definition.actions
        administers = "*" in actions
        changes_access = administers or any(
            a in AUTHORIZATION_ACTIONS or a.startswith("Microsoft.Authorization/roleAssignments")
            for a in actions
        )
        writes = administers or any(
            a.endswith(("/write", "/delete", "/action", "/*")) for a in actions
        )
        reads = writes or any(a.endswith("/read") for a in actions)
        return capability_document(
            "azure", name, "subscription", administers=administers,
            changes_access=changes_access, writes=writes, reads=reads,
            actions=actions + [f"not {a}" for a in definition.not_actions],
        )
    administers = name in AZURE_ADMINISTERS
    changes_access = administers or name in AZURE_CHANGES_ACCESS
    writes = changes_access or name.endswith(("Contributor", "Administrator", "Operator"))
    reads = writes or name.endswith("Reader")
    return capability_document(
        "azure", name, "subscription", administers=administers, changes_access=changes_access,
        writes=writes, reads=reads,
    )


def tenant_scope(db: Session, export: ParsedTenant) -> tuple[ProviderInstance, ScopeNode]:
    partition = Partition.azure_government if export.government else Partition.azure_commercial
    node = find_or_create_node(
        db, Provider.azure, partition, "tenant", export.id, export.display_name, None
    )
    provider = db.execute(
        select(ProviderInstance).where(
            ProviderInstance.provider == Provider.azure.value,
            ProviderInstance.root_scope_node_id == node.id,
        )
    ).scalar_one_or_none()
    if provider is None:
        provider = ProviderInstance(
            provider=Provider.azure.value, display_name=export.display_name,
            root_scope_node_id=node.id,
        )
        db.add(provider)
        db.flush()
    return provider, node


def tenant_node_id(db: Session, tenant_id: str) -> int | None:
    return db.execute(
        select(ScopeNode.id).where(
            ScopeNode.provider == Provider.azure.value,
            ScopeNode.kind == "tenant",
            ScopeNode.external_id == tenant_id,
        )
    ).scalar()


def import_tenant_export(
    db: Session,
    *,
    export: ParsedTenant,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    provider, tenant_node = tenant_scope(db, export)
    partition = Partition(tenant_node.partition)
    entity_count = (
        len(export.users) + len(export.groups) + len(export.service_principals)
        + sum(len(s.assignments) for s in export.subscriptions)
    )
    import_row = _new_import(
        db, provider, tenant_node, SOURCE_TENANT, captured_at, source_filename,
        actor_username, entity_count, export.skipped,
    )

    identities = {
        identity.external_id: identity
        for identity in db.execute(
            select(Identity).where(Identity.scope_node_id == tenant_node.id)
        ).scalars()
    }
    new_count = 0
    observations = 0
    observed: set[int] = set()
    definitions: dict[tuple[str, str], RoleDefinition] = {}

    def get_or_create(
        external_id: str, name: str, provider_type: str, kind: IdentityKind,
        home: Home = Home.this_directory, origin: str | None = None,
    ) -> Identity:
        nonlocal new_count
        identity = identities.get(external_id)
        if identity is None:
            identity = Identity(
                provider_id=provider.id, scope_node_id=tenant_node.id,
                external_id=external_id, provider_type=provider_type, kind=kind,
                home=home, origin=origin, first_display_name=name[:255], provisional=False,
            )
            db.add(identity)
            db.flush()
            identities[external_id] = identity
            new_count += 1
        return identity

    def observe(identity: Identity, display_name: str, provider_ref: str, **fields: object) -> None:
        nonlocal observations
        if identity.id in observed:
            return
        observed.add(identity.id)
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id, display_name=display_name[:255],
            provider_ref=provider_ref[:2048], **fields,
        ))
        observations += 1

    by_id: dict[str, Identity] = {}

    for user in export.users:
        if user.guest:
            identity = get_or_create(
                f"user:{user.id}", user.display_name, "user", IdentityKind.external,
                home=Home.other_tenant, origin="guest",
            )
        else:
            identity = get_or_create(
                f"user:{user.id}", user.display_name, "user", IdentityKind.unknown,
            )
        by_id[user.id] = identity
        observe(
            identity, user.display_name, user.principal_name,
            identity_created_at=user.created, mfa_active=user.mfa_registered,
            last_activity=user.last_sign_in,
            raw={"userPrincipalName": user.principal_name, "accountEnabled": user.enabled},
        )
        if not user.guest:
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id,
                kind=CredentialKind.password, external_id="sign-in", active=user.enabled,
                last_used=user.last_sign_in,
            ))

    for principal in export.service_principals:
        kind = (IdentityKind.workload if principal.kind == "ManagedIdentity"
                else IdentityKind.service)
        identity = get_or_create(
            f"sp:{principal.id}", principal.display_name, principal.kind.lower(), kind,
        )
        by_id[principal.id] = identity
        observe(
            identity, principal.display_name, principal.app_id or principal.id,
            raw={"appId": principal.app_id, "servicePrincipalType": principal.kind,
                 "accountEnabled": principal.enabled},
        )
        for credential in principal.credentials:
            expired = credential.end is not None and credential.end <= captured_at
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id,
                kind=(CredentialKind.client_secret if credential.kind == "secret"
                      else CredentialKind.certificate),
                external_id=credential.id, active=principal.enabled and not expired,
                created_at_provider=credential.start, expires_at=credential.end,
            ))

    for group in export.groups:
        identity = get_or_create(
            f"group:{group.id}", group.display_name, "group", IdentityKind.group,
        )
        by_id[group.id] = identity
        observe(identity, group.display_name, group.id)

    # Memberships, with a group inside a group passing its members up.
    direct: dict[str, list[ParsedMember]] = {g.id: g.members for g in export.groups}

    def members_of(group_id: str, seen: set[str]) -> list[str]:
        out: list[str] = []
        for member in direct.get(group_id, []):
            if member.kind == "group":
                if member.id not in seen:
                    seen.add(member.id)
                    out.extend(members_of(member.id, seen))
            else:
                out.append(member.id)
        return out

    written: set[tuple[int, int]] = set()
    for group in export.groups:
        group_identity = by_id[group.id]
        for member_id in members_of(group.id, {group.id}):
            member_identity = by_id.get(member_id)
            if member_identity is None or (member_identity.id, group_identity.id) in written:
                continue
            written.add((member_identity.id, group_identity.id))
            db.add(Membership(
                import_id=import_row.id, member_id=member_identity.id,
                group_id=group_identity.id, mode="active",
            ))

    def principal_identity(principal_id: str, name: str | None, principal_type: str) -> Identity:
        known = by_id.get(principal_id)
        if known is not None:
            return known
        # The assignment names something the directory did not list:
        # a foreign group, a principal from another tenant, or one that
        # was deleted after the assignment was made.
        origin = "foreign" if principal_type == "ForeignGroup" else "unresolved"
        identity = get_or_create(
            f"principal:{principal_id}", name or principal_id, principal_type.lower(),
            IdentityKind.external, home=Home.other_tenant, origin=origin,
        )
        observe(identity, name or principal_id, principal_id)
        by_id[principal_id] = identity
        return identity

    # Directory roles: members hold them standing, eligibilities in the
    # eligible mode, both at the tenant.
    template_names = {r.template_id: r.display_name for r in export.directory_roles}
    directory_definitions: dict[str, RoleDefinition] = {}

    def directory_definition(template_id: str, name: str) -> RoleDefinition:
        if template_id not in directory_definitions:
            directory_definitions[template_id] = role_definition_for(
                db, provider, f"azure:directory-role:{template_id}", name, "provider",
                directory_role_capabilities(name, template_id), import_row, definitions,
            )
        return directory_definitions[template_id]

    for role in export.directory_roles:
        definition = directory_definition(role.template_id, role.display_name)
        for member in role.members:
            identity = principal_identity(member.id, None, member.kind)
            db.add(Grant(
                import_id=import_row.id, identity_id=identity.id,
                role_definition_id=definition.id, scope_node_id=tenant_node.id,
                mode=GrantMode.standing, path=list(DIRECT),
                source_kind="directory_role", source_ref=role.display_name[:2048],
            ))
    eligible = 0
    for row in export.eligibilities:
        if row.end is not None and row.end <= captured_at:
            continue
        name = template_names.get(row.role_definition_id, row.role_definition_id)
        definition = directory_definition(row.role_definition_id, name)
        identity = principal_identity(row.principal_id, None, "Unknown")
        db.add(Grant(
            import_id=import_row.id, identity_id=identity.id,
            role_definition_id=definition.id, scope_node_id=tenant_node.id,
            mode=GrantMode.eligible, path=list(DIRECT),
            source_kind="role_eligibility", source_ref=row.scope_id[:2048],
        ))
        eligible += 1

    # Subscriptions, resource groups, and the assignments at each.
    described = {d.id: d for d in export.role_definitions}
    azure_definitions: dict[str, RoleDefinition] = {}

    def azure_definition(definition_id: str, name: str) -> RoleDefinition:
        if definition_id not in azure_definitions:
            listed = described.get(definition_id)
            azure_definitions[definition_id] = role_definition_for(
                db, provider, f"azure:role:{definition_id}", name,
                "customer" if listed is not None and listed.custom else "provider",
                azure_role_capabilities(name, listed), import_row, definitions,
            )
        return azure_definitions[definition_id]

    assignments = 0
    for subscription in export.subscriptions:
        sub_node = find_or_create_node(
            db, Provider.azure, partition, "subscription", subscription.id,
            subscription.display_name, tenant_node,
        )
        group_nodes: dict[str, ScopeNode] = {}
        for assignment in subscription.assignments:
            node = sub_node
            if assignment.resource_group is not None:
                key = assignment.resource_group.lower()
                if key not in group_nodes:
                    group_nodes[key] = find_or_create_node(
                        db, Provider.azure, partition, "resource_group",
                        f"{subscription.id}/resourceGroups/{key}", assignment.resource_group,
                        sub_node,
                    )
                node = group_nodes[key]
            definition = azure_definition(assignment.role_definition_id, assignment.role_name)
            identity = principal_identity(
                assignment.principal_id, assignment.principal_name, assignment.principal_type,
            )
            db.add(Grant(
                import_id=import_row.id, identity_id=identity.id,
                role_definition_id=definition.id, scope_node_id=node.id,
                mode=GrantMode.standing, path=list(DIRECT),
                source_kind="role_assignment", source_ref=assignment.scope[:2048],
            ))
            assignments += 1

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"tenant {export.id}",
        detail=(
            f"source {SOURCE_TENANT}, captured {captured_at.isoformat()}, "
            f"{observations} observations, {new_count} new identities, "
            f"{len(export.directory_roles)} directory roles, {eligible} eligibilities, "
            f"{len(export.subscriptions)} subscriptions, {assignments} assignments"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=export.id,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=0,
        observations=observations,
        skipped_rows=export.skipped,
    )
