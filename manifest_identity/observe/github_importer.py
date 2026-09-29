"""The GitHub importer: the second provider on the neutral tables.

The GitHub vocabulary becomes the neutral one here and nowhere else,
under the same transaction discipline as the AWS importers: one import
row, every identity, observation, credential, grant, membership, and
relationship, and the audit line, commit together or not at all, and
nothing is ever updated in place.

What each GitHub thing becomes:

- The organization is a scope node of kind organization under the
  github_com partition, and each repository is a node beneath it, so a
  grant on one repository is a grant at that repository's node.
- A member is an identity keyed by GitHub's numeric id. Every member
  signs in with a password, which the export does not carry but the
  platform's model guarantees, so a password credential row is written
  for each; whether a second factor protects it is the observation's
  MFA field, read from the export's two-factor state. Activity comes
  from the audit log's newest event per actor, when the export carries
  it.
- An outside collaborator is a guest: an identity whose home is another
  tenant, holding whatever a repository granted it directly, so that a
  contractor with admin on a repository shows in the inventory beside
  the members.
- A team is an identity of kind group with a membership row per member.
  A child team's members are members of its parent, which is GitHub's
  own rule, so those memberships are written too and the nesting is
  recorded as a relationship.
- An app installation is an identity of kind application. Its
  permissions map is its own role definition, customer managed and
  versioned by hash like any other, so an app that quietly gains
  administration is a changed definition.
- A deploy key is a credential nobody signs in with, so it is an
  identity of kind service holding one ssh_key credential and one
  grant on its repository, read or write.
- A fine-grained token is a credential row on its owner.
- Organization roles and the five repository permission levels are
  provider-managed role definitions whose contents are a capability
  document: what the level can do, in the neutral terms the privilege
  reading already speaks. The reading never learns the word maintain.
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
    Import,
    Membership,
    ObservedRelationship,
    ProviderInstance,
    RoleDefinition,
)
from manifest_identity.observe.policy_analysis import capability_document
from manifest_identity.observe.providers.github.organization_export import (
    ParsedOrganization,
)

SOURCE_ORGANIZATION = "github_organization"

# What each level can do, in the reading's own terms. An organization
# owner and a repository admin administer their scope outright; a
# member holds nothing by the role alone; maintain and write change
# contents but never access.
ORGANIZATION_LEVELS: dict[str, dict[str, bool]] = {
    "owner": {"administers": True, "changes_access": True, "writes": True, "reads": True},
    "member": {"administers": False, "changes_access": False, "writes": False, "reads": True},
    "billing_manager": {
        "administers": False, "changes_access": False, "writes": False, "reads": False,
    },
}
REPOSITORY_LEVELS: dict[str, dict[str, bool]] = {
    "admin": {"administers": True, "changes_access": True, "writes": True, "reads": True},
    "maintain": {"administers": False, "changes_access": False, "writes": True, "reads": True},
    "write": {"administers": False, "changes_access": False, "writes": True, "reads": True},
    "triage": {"administers": False, "changes_access": False, "writes": False, "reads": True},
    "read": {"administers": False, "changes_access": False, "writes": False, "reads": True},
}
# An app administers the organization when it may write administration
# or members; those two scopes are the ones that change who holds what.
ADMINISTERING_SCOPES = ("administration", "organization_administration", "members")

DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def level_document(level: str, scope: str, table: dict[str, bool]) -> dict[str, object]:
    """One fixed level's capability document, its four flags named."""
    return capability_document(
        "github", level, scope,
        administers=table["administers"], changes_access=table["changes_access"],
        writes=table["writes"], reads=table["reads"],
    )


def github_organization_scope(
    db: Session, login: str
) -> tuple[ProviderInstance, ScopeNode]:
    """The organization node and the GitHub provider row that names it
    as its root. There is one partition, github.com; an enterprise
    server would be a second partition and a second root."""
    node = find_or_create_node(
        db, Provider.github, Partition.github_com, "organization", login, login, None
    )
    provider = db.execute(
        select(ProviderInstance).where(
            ProviderInstance.provider == Provider.github.value,
            ProviderInstance.root_scope_node_id == node.id,
        )
    ).scalar_one_or_none()
    if provider is None:
        provider = ProviderInstance(
            provider=Provider.github.value, display_name=login, root_scope_node_id=node.id,
        )
        db.add(provider)
        db.flush()
    return provider, node


def organization_node_id(db: Session, login: str) -> int | None:
    return db.execute(
        select(ScopeNode.id).where(
            ScopeNode.provider == Provider.github.value,
            ScopeNode.kind == "organization",
            ScopeNode.external_id == login,
        )
    ).scalar()


def import_github_organization(
    db: Session,
    *,
    export: ParsedOrganization,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    provider, org_node = github_organization_scope(db, export.login)
    entity_count = (
        len(export.members) + len(export.outside_collaborators) + len(export.teams)
        + len(export.installations)
        + sum(len(r.deploy_keys) for r in export.repositories)
    )
    import_row = _new_import(
        db, provider, org_node, SOURCE_ORGANIZATION, captured_at, source_filename,
        actor_username, entity_count, export.skipped,
    )

    identities = {
        identity.external_id: identity
        for identity in db.execute(
            select(Identity).where(Identity.scope_node_id == org_node.id)
        ).scalars()
    }
    new_count = 0
    observations = 0
    definitions: dict[tuple[str, str], RoleDefinition] = {}

    def get_or_create(
        external_id: str, name: str, provider_type: str, kind: IdentityKind,
        home: Home = Home.this_directory, origin: str | None = None,
    ) -> Identity:
        nonlocal new_count
        identity = identities.get(external_id)
        if identity is not None:
            return identity
        identity = Identity(
            provider_id=provider.id, scope_node_id=org_node.id,
            external_id=external_id, provider_type=provider_type, kind=kind,
            home=home, origin=origin, first_display_name=name, provisional=False,
        )
        db.add(identity)
        db.flush()
        identities[external_id] = identity
        new_count += 1
        return identity

    def definition(
        external_id: str, name: str, managed_by: str, document: dict[str, object],
    ) -> RoleDefinition:
        return role_definition_for(
            db, provider, external_id, name, managed_by, document, import_row, definitions,
        )

    def grant(
        identity: Identity, role: RoleDefinition, node: ScopeNode, source_kind: str,
        source_ref: str,
    ) -> None:
        db.add(Grant(
            import_id=import_row.id, identity_id=identity.id, role_definition_id=role.id,
            scope_node_id=node.id, mode=GrantMode.standing, path=list(DIRECT),
            source_kind=source_kind, source_ref=source_ref[:2048],
        ))

    # Repository nodes first, so grants have a place to point.
    repository_nodes: dict[str, ScopeNode] = {}
    for repository in export.repositories:
        full = f"{export.login}/{repository.name}"
        repository_nodes[repository.name] = find_or_create_node(
            db, Provider.github, Partition.github_com, "repository", full, full, org_node,
        )

    def repository_level(name: str, level: str) -> RoleDefinition:
        full = f"{export.login}/{name}"
        return definition(
            f"github:repository:{full}:{level}", f"{level} on {full}", "provider",
            level_document(level, "repository", REPOSITORY_LEVELS[level]),
        )

    # Members: the identity, its observation with the second-factor
    # state and activity, its password, and its organization role.
    by_login: dict[str, Identity] = {}
    for member in export.members:
        identity = get_or_create(f"user:{member.id}", member.login, "user", IdentityKind.unknown)
        by_login[member.login] = identity
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id, display_name=member.login,
            provider_ref=member.login, identity_created_at=member.created_at,
            mfa_active=member.two_factor_enabled, last_activity=member.last_active_at,
        ))
        db.add(Credential(
            import_id=import_row.id, identity_id=identity.id,
            kind=CredentialKind.password, external_id="sign-in", active=True,
        ))
        role = definition(
            f"github:organization:{export.login}:{member.role}",
            f"{member.role.replace('_', ' ')} of {export.login}", "provider",
            level_document(member.role, "organization", ORGANIZATION_LEVELS[member.role]),
        )
        grant(identity, role, org_node, "organization_role", member.role)
        observations += 1

    # Outside collaborators are guests: seen, never members.
    for collaborator in export.outside_collaborators:
        identity = get_or_create(
            f"user:{collaborator.id}", collaborator.login, "user", IdentityKind.external,
            home=Home.other_tenant, origin="outside_collaborator",
        )
        by_login[collaborator.login] = identity
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id,
            display_name=collaborator.login, provider_ref=collaborator.login,
        ))
        observations += 1

    # Tokens ride on their owners.
    for token in export.tokens:
        owner = by_login[token.owner_login]
        db.add(Credential(
            import_id=import_row.id, identity_id=owner.id, kind=CredentialKind.token,
            external_id=f"token:{token.id}", active=not token.expired,
            created_at_provider=token.created_at, last_used=token.last_used_at,
            expires_at=token.expires_at,
        ))

    # Teams: the group identity, its repository grants, and its members,
    # with a child's members counted as the parent's too.
    teams_by_slug: dict[str, Identity] = {}
    for team in export.teams:
        group = get_or_create(f"team:{team.id}", team.name, "team", IdentityKind.group)
        teams_by_slug[team.slug] = group
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=group.id, display_name=team.name,
            provider_ref=team.slug,
        ))
        for name, level in team.repositories:
            grant(
                group, repository_level(name, level), repository_nodes[name],
                "team_permission", f"{team.slug}:{name}",
            )
    parents = {t.slug: t.parent_slug for t in export.teams}
    written: set[tuple[int, int]] = set()
    for team in export.teams:
        chain: list[str] = []
        slug: str | None = team.slug
        while slug is not None and slug not in chain:
            chain.append(slug)
            slug = parents.get(slug)
        for login in team.member_logins:
            member_identity = by_login[login]
            for ancestor in chain:
                key = (member_identity.id, teams_by_slug[ancestor].id)
                if key in written:
                    continue
                written.add(key)
                db.add(Membership(
                    import_id=import_row.id, member_id=member_identity.id,
                    group_id=teams_by_slug[ancestor].id, mode="active",
                ))
        if team.parent_slug is not None:
            db.add(ObservedRelationship(
                import_id=import_row.id, kind="group_nesting",
                to_identity_id=teams_by_slug[team.parent_slug].id,
                from_ref=team.slug, from_kind="team",
            ))

    # Repositories: direct collaborators and deploy keys.
    for repository in export.repositories:
        node = repository_nodes[repository.name]
        for login, level in repository.collaborators:
            grant(
                by_login[login], repository_level(repository.name, level), node,
                "repository_permission", repository.name,
            )
        for deploy_key in repository.deploy_keys:
            identity = get_or_create(
                f"deploy_key:{deploy_key.id}", deploy_key.title, "deploy_key",
                IdentityKind.service,
            )
            db.add(IdentityObservation(
                import_id=import_row.id, identity_id=identity.id,
                display_name=deploy_key.title,
                provider_ref=f"{export.login}/{repository.name}#deploy-key-{deploy_key.id}",
                identity_created_at=deploy_key.created_at, last_activity=deploy_key.last_used,
            ))
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id, kind=CredentialKind.ssh_key,
                external_id=f"deploy_key:{deploy_key.id}", active=True,
                created_at_provider=deploy_key.created_at, last_used=deploy_key.last_used,
            ))
            level = "read" if deploy_key.read_only else "write"
            grant(
                identity, repository_level(repository.name, level), node,
                "deploy_key", repository.name,
            )
            observations += 1

    # Installations: an application whose permissions are its own
    # definition, versioned by hash.
    for installation in export.installations:
        identity = get_or_create(
            f"installation:{installation.id}", installation.app_slug, "installation",
            IdentityKind.application,
        )
        db.add(IdentityObservation(
            import_id=import_row.id, identity_id=identity.id,
            display_name=installation.app_slug,
            provider_ref=f"{export.login}#installation-{installation.id}",
            identity_created_at=installation.created_at,
            raw={
                "permissions": installation.permissions,
                "repository_selection": installation.repository_selection,
            },
        ))
        administers = any(
            installation.permissions.get(scope) in ("write", "admin")
            for scope in ADMINISTERING_SCOPES
        )
        writes = any(level in ("write", "admin") for level in installation.permissions.values())
        document = capability_document(
            "github", "installation", "organization",
            administers=administers, changes_access=administers, writes=writes,
            reads=bool(installation.permissions),
        )
        document["permissions"] = dict(sorted(installation.permissions.items()))
        role = definition(
            f"github:installation:{installation.app_slug}:permissions",
            f"{installation.app_slug} permissions", "customer", document,
        )
        grant(identity, role, org_node, "installation", installation.app_slug)
        observations += 1

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"organization {export.login}",
        detail=(
            f"source {SOURCE_ORGANIZATION}, captured {captured_at.isoformat()}, "
            f"{observations} observations, {new_count} new identities, "
            f"{len(export.teams)} teams, {len(export.repositories)} repositories, "
            f"{len(export.installations)} installations"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=export.login,
        captured_at=captured_at,
        identities_new=new_count,
        identities_known=0,
        observations=observations,
        skipped_rows=export.skipped,
    )


def newest_organization_import(db: Session, node_id: int) -> int | None:
    return db.execute(
        select(Import.id)
        .where(Import.scope_node_id == node_id, Import.source_kind == SOURCE_ORGANIZATION)
        .order_by(Import.captured_at.desc(), Import.id.desc())
        .limit(1)
    ).scalar()
