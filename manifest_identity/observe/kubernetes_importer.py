"""The Kubernetes importer: the third provider on the neutral tables.

The cluster's vocabulary becomes the neutral one here and nowhere
else, under the transaction discipline the other importers keep.

What each thing becomes:

- The cluster is a scope node of kind cluster, named by the form field
  that arrives beside the file, since nothing in the file names it;
  each namespace a binding or an account mentions is a node beneath it.
- A ServiceAccount is an identity of kind service, keyed by namespace
  and name, because that is how every binding refers to it; the uid
  the cluster never reuses rides in the observation. A recreated
  account with the same name is therefore the same identity here,
  which is the binding's view and is stated as a limit.
- A User subject is an identity the cluster never lists: the
  authenticator asserts the name. It is recorded as home
  identity_provider, kind unknown, seen only through its bindings.
- A Group subject is likewise asserted from outside, and the cluster
  cannot list its members, so it is recorded as an external identity
  holding whatever its bindings grant, with no membership rows. The two
  groups the cluster itself defines are the exception: system:
  serviceaccounts and system:serviceaccounts:<namespace> contain every
  service account, or every one in that namespace, by the API's own
  rule, so they are groups with membership rows written.
- A Role or ClusterRole is a definition keyed by kind and name (and
  namespace for a Role), provider managed when its name starts with
  system: or is one of the four the API ships (cluster-admin, admin,
  edit, view), customer managed otherwise. Its contents are a
  capability document read from its rules: a rule allowing every verb
  on every resource administers; bind, escalate, and impersonate, or
  any write on the role and binding resources, change access; any
  mutating verb writes; get, list, and watch read. The rules ride in
  the document as actions, one per verb and resource, so a changed
  role names what it gained.
- A binding is one grant per subject: at the namespace node for a
  RoleBinding, at the cluster node for a ClusterRoleBinding. A
  RoleBinding that references a ClusterRole grants that cluster role
  inside its namespace, which is the API's rule. A binding to a role
  the file does not hold is a grant of a definition with no contents,
  so the reading says nothing about it rather than guessing.
- No credentials: the dump carries none. Service account tokens are
  minted on demand by the current API and are not objects to list.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from manifest_identity.core import audit
from manifest_identity.core.models import Partition, Provider, ScopeNode
from manifest_identity.core.scope import find_or_create_node
from manifest_identity.observe.estate import Estate, provider_root
from manifest_identity.observe.importer import (
    ImportResult,
    _check_capture,
    _commit_or_duplicate,
    _new_import,
    role_definition_for,
)
from manifest_identity.observe.models import (
    Grant,
    GrantMode,
    Home,
    Identity,
    IdentityKind,
    Membership,
    RoleDefinition,
)
from manifest_identity.observe.policy_analysis import capability_document
from manifest_identity.observe.providers.kubernetes.rbac_dump import (
    ParsedDump,
    ParsedRole,
    ParsedSubject,
)

SOURCE_RBAC = "kubernetes_rbac"

SHIPPED_ROLES = frozenset({"cluster-admin", "admin", "edit", "view"})
ACCESS_RESOURCES = frozenset({"roles", "clusterroles", "rolebindings", "clusterrolebindings"})
ACCESS_VERBS = frozenset({"bind", "escalate", "impersonate"})
WRITE_VERBS = frozenset({"create", "update", "patch", "delete", "deletecollection"})
READ_VERBS = frozenset({"get", "list", "watch"})
ALL_SERVICE_ACCOUNTS = "system:serviceaccounts"

DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]


def role_capabilities(role: ParsedRole) -> dict[str, object]:  # noqa: C901
    """What a role can do, in the reading's terms, from its rules."""
    administers = changes_access = writes = reads = False
    actions: list[str] = []
    for rule in role.rules:
        verbs = set(rule.verbs)
        resources = set(rule.resources)
        every_verb = "*" in verbs
        every_resource = "*" in resources
        # resourceNames limits a rule to the objects it names, so even
        # every verb on every resource is not the whole cluster. Binding
        # one named role can still change access, so that stays.
        named = rule.resource_names
        if every_verb and every_resource and not named:
            administers = True
        if verbs & ACCESS_VERBS:
            changes_access = True
        if (every_verb or verbs & WRITE_VERBS) and (every_resource or resources & ACCESS_RESOURCES):
            changes_access = True
        if every_verb or verbs & WRITE_VERBS:
            writes = True
        if every_verb or verbs & READ_VERBS:
            reads = True
        groups = rule.api_groups or [""]
        for verb in rule.verbs:
            for group in groups:
                for resource in rule.resources:
                    action = f"{verb} {group + '/' if group else ''}{resource}"
                    actions.extend([f"{action}/{name}" for name in named] or [action])
            for url in rule.non_resource_urls:
                actions.append(f"{verb} {url}")
    return capability_document(
        "kubernetes", role.name, "namespace" if role.kind == "Role" else "cluster",
        administers=administers, changes_access=changes_access, writes=writes, reads=reads,
        actions=actions,
    )


def managed_by(name: str) -> str:
    return "provider" if name.startswith("system:") or name in SHIPPED_ROLES else "customer"


def subject_key(subject: ParsedSubject) -> str:
    if subject.kind == "ServiceAccount":
        return f"serviceaccount:{subject.namespace}/{subject.name}"
    return f"{subject.kind.lower()}:{subject.name}"


def import_rbac_dump(  # noqa: C901
    db: Session,
    *,
    dump: ParsedDump,
    cluster: str,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    provider, cluster_node = provider_root(
        db, Provider.kubernetes, Partition.none, "cluster", cluster, cluster,
    )
    import_row = _new_import(
        db, provider, cluster_node, SOURCE_RBAC, captured_at, source_filename,
        actor_username, len(dump.roles) + len(dump.bindings) + len(dump.service_accounts),
        dump.skipped,
    )

    estate = Estate(db, import_row, provider, cluster_node)
    identities = estate.identities
    definitions: dict[tuple[str, str], RoleDefinition] = {}
    namespaces: dict[str, ScopeNode] = {}

    def namespace_node(name: str) -> ScopeNode:
        if name not in namespaces:
            namespaces[name] = find_or_create_node(
                db, Provider.kubernetes, Partition.none, "namespace", f"{cluster}/{name}",
                name, cluster_node,
            )
        return namespaces[name]

    get_or_create = estate.get_or_create

    def observe(identity: Identity, display_name: str, provider_ref: str,
                created: datetime | None = None, raw: dict[str, object] | None = None) -> None:
        estate.observe(identity, display_name, provider_ref, identity_created_at=created, raw=raw)

    # Service accounts first, so the cluster's own groups can list them.
    accounts_by_namespace: dict[str, list[Identity]] = {}
    for account in dump.service_accounts:
        identity = get_or_create(
            f"serviceaccount:{account.namespace}/{account.name}",
            f"{account.namespace}/{account.name}", "serviceaccount", IdentityKind.service,
        )
        observe(
            identity, f"{account.namespace}/{account.name}",
            f"system:serviceaccount:{account.namespace}:{account.name}", account.created,
            {"uid": account.uid} if account.uid else None,
        )
        accounts_by_namespace.setdefault(account.namespace, []).append(identity)
        namespace_node(account.namespace)

    # Roles become definitions with their capabilities read from rules.
    def role_key(kind: str, namespace: str | None, name: str) -> str:
        return f"role:{namespace}/{name}" if kind == "Role" else f"clusterrole:{name}"

    known: dict[str, RoleDefinition] = {}
    for role in dump.roles:
        key = role_key(role.kind, role.namespace, role.name)
        known[key] = role_definition_for(
            db, provider, key, role.name, managed_by(role.name), role_capabilities(role),
            import_row, definitions,
        )
        if role.namespace:
            namespace_node(role.namespace)

    def subject_identity(subject: ParsedSubject) -> Identity:
        key = subject_key(subject)
        if subject.kind == "ServiceAccount":
            identity = get_or_create(
                key, f"{subject.namespace}/{subject.name}", "serviceaccount",
                IdentityKind.service,
            )
            observe(identity, f"{subject.namespace}/{subject.name}",
                    f"system:serviceaccount:{subject.namespace}:{subject.name}")
            return identity
        if subject.kind == "User":
            identity = get_or_create(
                key, subject.name, "user", IdentityKind.unknown,
                home=Home.identity_provider, origin="subject",
            )
            observe(identity, subject.name, subject.name)
            return identity
        # A group. The cluster's own two are groups with members; any
        # other is asserted from outside and its members are unknown.
        if subject.name == ALL_SERVICE_ACCOUNTS or subject.name.startswith(
            ALL_SERVICE_ACCOUNTS + ":"
        ):
            identity = get_or_create(key, subject.name, "group", IdentityKind.group)
            observe(identity, subject.name, subject.name)
            return identity
        identity = get_or_create(
            key, subject.name, "group", IdentityKind.external,
            home=Home.identity_provider, origin="subject",
        )
        observe(identity, subject.name, subject.name)
        return identity

    dangling = 0
    for binding in dump.bindings:
        key = role_key(binding.role_kind, binding.namespace, binding.role_name)
        definition = known.get(key)
        if definition is None:
            # The API allows a binding to a role that does not exist;
            # the grant is recorded against a definition with no
            # contents, and counted, so the gap is a number.
            dangling += 1
            definition = role_definition_for(
                db, provider, key, binding.role_name, managed_by(binding.role_name), None,
                import_row, definitions,
            )
            known[key] = definition
        node = namespace_node(binding.namespace) if binding.namespace else cluster_node
        source_kind = binding.kind.lower()
        source_ref = f"{binding.namespace}/{binding.name}" if binding.namespace else binding.name
        for subject in binding.subjects:
            identity = subject_identity(subject)
            db.add(Grant(
                import_id=import_row.id, identity_id=identity.id,
                role_definition_id=definition.id, scope_node_id=node.id,
                mode=GrantMode.standing, path=list(DIRECT),
                source_kind=source_kind, source_ref=source_ref[:2048],
            ))

    # The cluster's own groups: every service account is a member of
    # system:serviceaccounts, and of the group for its namespace.
    written: set[tuple[int, int]] = set()
    for group_key, group in identities.items():
        if group.kind != IdentityKind.group or not estate.observed(group):
            continue
        name = group_key.removeprefix("group:")
        if name == ALL_SERVICE_ACCOUNTS:
            members = [sa for accounts in accounts_by_namespace.values() for sa in accounts]
        elif name.startswith(ALL_SERVICE_ACCOUNTS + ":"):
            members = accounts_by_namespace.get(name.split(":", 2)[2], [])
        else:
            continue
        for member in members:
            if (member.id, group.id) in written:
                continue
            written.add((member.id, group.id))
            db.add(Membership(
                import_id=import_row.id, member_id=member.id, group_id=group.id, mode="active",
            ))

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"cluster {cluster}",
        detail=(
            f"source {SOURCE_RBAC}, captured {captured_at.isoformat()}, "
            f"{estate.observations} observations, {estate.new_count} new identities, "
            f"{len(dump.roles)} roles, {len(dump.bindings)} bindings, "
            f"{dangling} bindings to roles the file does not hold, "
            f"{dump.skipped} objects skipped"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=cluster,
        captured_at=captured_at,
        identities_new=estate.new_count,
        identities_known=0,
        observations=estate.observations,
        skipped_rows=dump.skipped,
    )
