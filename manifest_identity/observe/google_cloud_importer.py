"""The Google Cloud importer: the fourth provider on the neutral tables.

The provider's vocabulary becomes the neutral one here and nowhere
else, under the transaction discipline the other importers keep.

What each thing becomes:

- The project is a scope node of kind project under the gcp partition.
  An organization and its folders arrive when the asset export is the
  source; a project export knows only its project.
- A service account is an identity of kind service keyed by the
  uniqueId the provider never reuses, with each user-managed key as an
  access_key credential carrying its validity window, so key age and
  a rotation that never finished read through the findings the AWS
  keys read through. Google-managed keys rotate on their own and are
  not credentials anyone holds, so they are not rows. Activity comes
  from the activity analyzer when the export carries it; an account
  with keys and no activity reads as unused, which is true of the
  export and is the reason the field exists.
- A user member is an identity of kind unknown seen only through its
  bindings: the project's policy says who holds a role and nothing
  about how they sign in, so no credential is written and the second
  factor state is unknown.
- A group member is a Google group whose members the project cannot
  list, so it enters as an external identity from an identity provider
  holding whatever its bindings grant, with no membership rows; a
  domain member is the same for everyone in a domain.
- The two public forms, allUsers and allAuthenticatedUsers, enter as
  guests from the consumer world, so a public grant shows as a guest
  named for what it is holding a role.
- A deleted principal a policy still names enters with origin deleted,
  so a binding nobody cleaned up shows in the delta as held by
  something that no longer exists.
- A federated principal enters as an identity from an identity
  provider with origin federation.
- A role is a definition: predefined roles are provider managed and
  custom roles customer managed. Its contents are a capability document
  read from its permission list when the export carries one, otherwise
  from a small table of the roles whose meaning is fixed (owner, editor,
  viewer, the administration roles, the service account roles) and a
  reading of the role's name for the rest. The permissions ride as
  actions, so a changed custom role names what it gained.
- A binding is one grant per member at the project node. A binding
  with a condition is a grant with the condition's title in its source
  reference and the condition itself unread, which is stated.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.models import Partition, Provider
from manifest_identity.observe.estate import Estate, provider_root
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
    RoleDefinition,
)
from manifest_identity.observe.policy_analysis import capability_document
from manifest_identity.observe.providers.google_cloud.project_export import (
    ParsedMember,
    ParsedProject,
)

SOURCE_PROJECT = "google_cloud_project"

# The roles whose meaning is fixed by the provider, in the reading's
# terms. Everything not here is read from its name or its permissions.
# Each entry is administers, changes access, writes, reads, in that order.
FIXED_ROLES: dict[str, tuple[bool, bool, bool, bool]] = {
    "roles/owner": (True, True, True, True),
    "roles/editor": (False, False, True, True),
    "roles/viewer": (False, False, False, True),
    "roles/browser": (False, False, False, True),
    "roles/resourcemanager.projectIamAdmin": (False, True, True, True),
    "roles/resourcemanager.organizationAdmin": (False, True, True, True),
    "roles/resourcemanager.folderAdmin": (False, True, True, True),
    "roles/iam.securityAdmin": (False, True, True, True),
    "roles/iam.organizationRoleAdmin": (False, True, True, True),
    "roles/iam.roleAdmin": (False, True, True, True),
    "roles/iam.serviceAccountAdmin": (False, True, True, True),
    "roles/iam.serviceAccountKeyAdmin": (False, True, True, True),
    "roles/iam.serviceAccountTokenCreator": (False, True, False, True),
    "roles/iam.serviceAccountUser": (False, True, False, True),
    "roles/iam.workloadIdentityUser": (False, True, False, True),
}
# Permissions that change who holds what or mint a credential.
ACCESS_PERMISSION_SUFFIXES = (".setIamPolicy",)
ACCESS_PERMISSIONS = frozenset({
    "iam.serviceAccountKeys.create", "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.getOpenIdToken", "iam.roles.create", "iam.roles.update",
    "iam.roles.delete",
})
WRITE_VERBS = (".create", ".update", ".delete", ".write", ".setIamPolicy", ".use", ".actAs")
READ_VERBS = (".get", ".list", ".read", ".export")
NAME_WRITES = ("admin", "editor", "user", "creator", "writer", "developer", "owner")
NAME_READS = ("viewer", "reader", "browser", "user", "creator", "writer", "developer",
              "admin", "editor", "owner")

DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def capabilities_from_permissions(name: str, permissions: list[str]) -> dict[str, object]:
    changes_access = any(
        p in ACCESS_PERMISSIONS or p.endswith(ACCESS_PERMISSION_SUFFIXES) for p in permissions
    )
    writes = any(p.endswith(WRITE_VERBS) for p in permissions)
    reads = any(p.endswith(READ_VERBS) for p in permissions)
    return capability_document(
        "gcp", name, "project", administers=False, changes_access=changes_access,
        writes=writes, reads=reads, actions=permissions,
    )


def capabilities_from_name(name: str) -> dict[str, object]:
    if name in FIXED_ROLES:
        administers, changes_access, writes, reads = FIXED_ROLES[name]
    else:
        last = name.rsplit("/", 1)[-1].split(".")[-1].lower()
        administers, changes_access = False, False
        writes = any(last.endswith(word) for word in NAME_WRITES)
        reads = any(last.endswith(word) for word in NAME_READS)
    return capability_document(
        "gcp", name, "project", administers=administers, changes_access=changes_access,
        writes=writes, reads=reads,
    )


def managed_by(name: str) -> str:
    return "provider" if name.startswith("roles/") else "customer"


def import_project_export(
    db: Session,
    *,
    export: ParsedProject,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    provider, node = provider_root(
        db, Provider.gcp, Partition.gcp, "project", export.project_id, export.project_id,
    )
    import_row = _new_import(
        db, provider, node, SOURCE_PROJECT, captured_at, source_filename, actor_username,
        len(export.service_accounts) + sum(len(b.members) for b in export.bindings),
        export.skipped,
    )

    estate = Estate(db, import_row, provider, node)
    get_or_create, observe = estate.get_or_create, estate.observe
    definitions: dict[tuple[str, str], RoleDefinition] = {}

    # Service accounts first, keyed by the identifier the provider never
    # reuses, so a binding can find them by address.
    by_email: dict[str, Identity] = {}
    for account in export.service_accounts:
        identity = get_or_create(
            f"serviceaccount:{account.unique_id}", account.email, "serviceaccount",
            IdentityKind.service,
        )
        by_email[account.email] = identity
        observe(
            identity, account.email, f"serviceAccount:{account.email}",
            last_activity=account.last_authenticated,
            raw={"displayName": account.display_name, "disabled": account.disabled},
        )
        for key in account.keys:
            if not key.user_managed:
                continue
            expired = key.valid_before is not None and key.valid_before <= captured_at
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id,
                kind=CredentialKind.access_key, external_id=key.id,
                active=not key.disabled and not expired and not account.disabled,
                created_at_provider=key.valid_after, expires_at=key.valid_before,
            ))

    def member_identity(member: ParsedMember) -> Identity:
        if member.kind == "serviceAccount":
            known = by_email.get(member.name)
            if known is not None:
                return known
            # A binding names an account the list does not hold (another
            # project's, or a Google-managed agent): a guest by address.
            identity = get_or_create(
                f"serviceaccount:{member.name}", member.name, "serviceaccount",
                IdentityKind.external, home=Home.other_tenant, origin="binding",
            )
            observe(identity, member.name, member.text)
            return identity
        if member.kind == "user":
            identity = get_or_create(
                f"user:{member.name}", member.name, "user", IdentityKind.unknown,
            )
            observe(identity, member.name, member.text)
            return identity
        kind_by_member = {
            "group": ("group", Home.identity_provider, "group"),
            "domain": ("domain", Home.identity_provider, "domain"),
            "public": ("public", Home.consumer, "public"),
            "deleted": ("deleted", Home.other_tenant, "deleted"),
            "federated": ("federated", Home.identity_provider, "federation"),
        }
        provider_type, home, origin = kind_by_member[member.kind]
        identity = get_or_create(
            f"{provider_type}:{member.name}", member.name, provider_type, IdentityKind.external,
            home=home, origin=origin,
        )
        observe(identity, member.name, member.text)
        return identity

    described = {d.name: d for d in export.role_definitions}

    def definition(role: str) -> RoleDefinition:
        listed = described.get(role)
        document = (
            capabilities_from_permissions(role, listed.permissions)
            if listed is not None else capabilities_from_name(role)
        )
        title = listed.title if listed is not None else role
        return role_definition_for(
            db, provider, role, title, managed_by(role), document, import_row, definitions,
        )

    conditioned = 0
    for binding in export.bindings:
        role = definition(binding.role)
        if binding.condition_title is not None:
            conditioned += 1
        for member in binding.members:
            identity = member_identity(member)
            db.add(Grant(
                import_id=import_row.id, identity_id=identity.id, role_definition_id=role.id,
                scope_node_id=node.id, mode=GrantMode.standing, path=list(DIRECT),
                source_kind="binding",
                source_ref=(f"condition:{binding.condition_title}" if binding.condition_title
                            is not None else "")[:2048],
            ))

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"project {export.project_id}",
        detail=(
            f"source {SOURCE_PROJECT}, captured {captured_at.isoformat()}, "
            f"{estate.observations} observations, {estate.new_count} new identities, "
            f"{len(export.bindings)} bindings of which {conditioned} conditioned, "
            f"{len(export.service_accounts)} service accounts"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=export.project_id,
        captured_at=captured_at,
        identities_new=estate.new_count,
        identities_known=0,
        observations=estate.observations,
        skipped_rows=export.skipped,
    )
