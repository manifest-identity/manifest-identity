"""The Active Directory importer: the seventh provider on the neutral
tables, fed by two doors.

The provider's vocabulary becomes the neutral one here and nowhere
else, under the transaction discipline the other importers keep. The
cmdlet document (D-083) and the SharpHound collection (D-084) both
arrive as one ParsedDomain, so one importer reads both and the second
door differs only in what it carries: the control rights.

What each thing becomes:

- The domain is a scope node of kind domain, keyed by its security
  identifier, which a directory never reuses, shown by its DNS name,
  in the on-premises partition. Every organizational unit an object
  sits in is a scope node beneath it, so an operator can be bound to
  one unit.
- A user is an identity keyed by its identifier, with a password
  credential active while the account is enabled, rotated when the
  password was last set, used at the last logon. A user with a
  service principal name also carries a Kerberos service key, because
  that is what a service principal name is: the account presents a
  key as well as a password, and the page reads that as a mixed
  identity, which is the classic service account that is a person's
  kind of account (D-083).
- A computer is an identity of kind workload keyed by its identifier,
  with its machine account as a Kerberos key, rotated when the
  directory last set it.
- A group is an identity of kind group with a membership row per
  member. A group inside a group is recorded as a nesting
  relationship, and the outer group's members are written for every
  group that contains it, the way the GitHub importer flattens teams,
  so the page's "through the group" names the group that holds the
  privilege. A member the file does not list is a foreign security
  principal from another domain: an external identity whose home is
  another directory.
- The built-in groups that hold the domain are provider-managed
  definitions read from a table of what each may do (D-083): the
  domain, enterprise, and built-in administrators administer; the
  account, backup, server, key, and DNS administrators, and the
  policy creator owners, change access, because each is a documented
  route to a domain administrator's key; the print operators write on
  the domain controllers; the remote groups read. Each such group
  holds a grant of its definition at the domain, and the membership
  hop carries it to the members.
- A control right from the collector, when not inherited, is a grant
  in the eligible mode: the principal can obtain what the target
  holds. Rights on the domain object reach a definition that
  administers the domain; rights on a privileged group reach that
  group's definition; rights on a direct member of a privileged group
  reach the same, because owning the member is owning the membership.
  A principal that already holds the definition standing, or that
  administers the domain outright, is not written again, so the
  defaults the directory grants its own administrators over every
  object do not fill the page (D-084).
- A trust is an observed relationship from the partner domain into
  this one, with its direction, type, and transitivity kept, so a
  door into the domain is on the record whether or not anyone walks
  through it.
"""

from __future__ import annotations

import re
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
    Credential,
    CredentialKind,
    Grant,
    GrantMode,
    Home,
    Identity,
    IdentityKind,
    Membership,
    ObservedRelationship,
    RoleDefinition,
)
from manifest_identity.observe.policy_analysis import capability_document
from manifest_identity.observe.providers.active_directory.directory_export import (
    ParsedAccount,
    ParsedDomain,
)

SOURCE_DOMAIN = "active_directory_domain"
SOURCE_SHARPHOUND = "active_directory_sharphound"

DIRECT = [{"via": "direct", "ref": "", "mode": "active"}]

# Each entry is administers, changes access, writes, reads, in that
# order, keyed by the relative identifier of a domain group or the
# whole identifier of a built-in one. The judgments are D-083's.
PRIVILEGED_GROUPS: dict[str, tuple[bool, bool, bool, bool]] = {
    "512": (True, True, True, True),  # Domain Admins
    "519": (True, True, True, True),  # Enterprise Admins
    "S-1-5-32-544": (True, True, True, True),  # Administrators
    "518": (False, True, True, True),  # Schema Admins
    "520": (False, True, True, True),  # Group Policy Creator Owners
    "526": (False, True, True, True),  # Key Admins
    "527": (False, True, True, True),  # Enterprise Key Admins
    "S-1-5-32-548": (False, True, True, True),  # Account Operators
    "S-1-5-32-549": (False, True, True, True),  # Server Operators
    "S-1-5-32-551": (False, True, True, True),  # Backup Operators
    "S-1-5-32-550": (False, False, True, True),  # Print Operators
    "S-1-5-32-555": (False, False, False, True),  # Remote Desktop Users
    "S-1-5-32-580": (False, False, False, True),  # Remote Management Users
}
# Groups without a fixed identifier, matched by their account name.
PRIVILEGED_NAMES: dict[str, tuple[bool, bool, bool, bool]] = {
    "dnsadmins": (False, True, True, True),
}
# Rights that only read something; every other right the collector
# writes is one the holder can use to take the object.
READ_ONLY_RIGHTS = frozenset({"ReadGMSAPassword", "ReadLAPSPassword", "GetChanges"})

_OU = re.compile(r"^OU=(.+)$", re.IGNORECASE)


def privileged_capabilities(sid: str, name: str) -> tuple[bool, bool, bool, bool] | None:
    """What a built-in group may do, or None for an ordinary group."""
    rid = sid.rsplit("-", 1)[-1]
    if sid.startswith("S-1-5-32-"):
        return PRIVILEGED_GROUPS.get(sid)
    return PRIVILEGED_GROUPS.get(rid) or PRIVILEGED_NAMES.get(name.lower())


def group_capabilities(sid: str, name: str) -> dict[str, object] | None:
    found = privileged_capabilities(sid, name)
    if found is None:
        return None
    administers, changes_access, writes, reads = found
    return capability_document(
        "active_directory", name, "domain", administers=administers,
        changes_access=changes_access, writes=writes, reads=reads,
    )


def domain_capabilities(dns_root: str) -> dict[str, object]:
    return capability_document(
        "active_directory", f"control of {dns_root}", "domain", administers=True,
        changes_access=True, writes=True, reads=True,
    )


def organizational_units(distinguished_name: str) -> list[str]:
    """The unit path from the domain down, as the components of the
    distinguished name below the object, outermost first."""
    parts = [p.strip() for p in re.split(r"(?<!\\),", distinguished_name)]
    units = [m.group(1) for p in parts[1:] if (m := _OU.match(p))]
    return list(reversed(units))


def import_domain(
    db: Session,
    *,
    domain: ParsedDomain,
    source_kind: str,
    captured_at: datetime,
    source_filename: str | None,
    actor_user_id: int,
    actor_username: str,
) -> ImportResult:
    captured_at = _check_capture(captured_at)
    provider, node = provider_root(
        db, Provider.active_directory, Partition.on_premises, "domain", domain.sid,
        domain.dns_root,
    )
    import_row = _new_import(
        db, provider, node, source_kind, captured_at, source_filename, actor_username,
        len(domain.users) + len(domain.groups) + len(domain.computers) + len(domain.aces),
        domain.skipped,
    )

    estate = Estate(db, import_row, provider, node)
    get_or_create = estate.get_or_create
    definitions: dict[tuple[str, str], RoleDefinition] = {}
    unit_nodes: dict[str, ScopeNode] = {}

    def unit_for(distinguished_name: str) -> str | None:
        """The organizational unit an object sits in, its node made on
        first sight with every unit above it."""
        units = organizational_units(distinguished_name)
        parent = node
        key = domain.sid
        for unit in units:
            key = f"{key}/{unit.lower()}"
            if key not in unit_nodes:
                unit_nodes[key] = find_or_create_node(
                    db, Provider.active_directory, Partition.on_premises,
                    "organizational_unit", key, unit, parent,
                )
            parent = unit_nodes[key]
        return "/".join(units) or None

    by_sid: dict[str, Identity] = {}

    def observe_account(account: ParsedAccount, computer: bool) -> Identity:
        identity = get_or_create(
            account.sid, account.sam_account_name, "computer" if computer else "user",
            IdentityKind.workload if computer else IdentityKind.unknown,
        )
        by_sid[account.sid] = identity
        estate.observe(
            identity, account.sam_account_name, account.distinguished_name,
            identity_created_at=account.created, last_activity=account.last_logon,
            raw={
                "enabled": account.enabled, "admin_count": account.admin_count,
                "service_principal_names": account.service_principal_names,
                "password_never_expires": account.password_never_expires,
                "organizational_unit": unit_for(account.distinguished_name),
                "description": account.description,
                "operating_system": account.operating_system,
            },
        )
        if computer:
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id,
                kind=CredentialKind.kerberos_key, external_id="machine account",
                active=account.enabled, last_rotated=account.password_last_set,
                last_used=account.last_logon, created_at_provider=account.created,
            ))
            return identity
        db.add(Credential(
            import_id=import_row.id, identity_id=identity.id,
            kind=CredentialKind.password, external_id="password", active=account.enabled,
            last_rotated=account.password_last_set, last_used=account.last_logon,
            created_at_provider=account.created,
        ))
        # A service principal name is a Kerberos service key the account
        # presents; a user carrying one is a service that can also sign
        # in, which the page reads as mixed (D-083).
        if account.service_principal_names:
            db.add(Credential(
                import_id=import_row.id, identity_id=identity.id,
                kind=CredentialKind.kerberos_key,
                external_id=account.service_principal_names[0][:255],
                active=account.enabled, last_rotated=account.password_last_set,
                last_used=account.last_logon, created_at_provider=account.created,
            ))
        return identity

    for user in domain.users:
        observe_account(user, computer=False)
    for computer in domain.computers:
        observe_account(computer, computer=True)

    groups_by_sid = {g.sid: g for g in domain.groups}
    for group in domain.groups:
        identity = get_or_create(group.sid, group.sam_account_name, "group", IdentityKind.group)
        by_sid[group.sid] = identity
        estate.observe(
            identity, group.sam_account_name, group.distinguished_name,
            raw={"scope": group.scope, "category": group.category,
                 "admin_count": group.admin_count,
                 "organizational_unit": unit_for(group.distinguished_name)},
        )

    def foreign(sid: str) -> Identity:
        """A member or principal from another domain, on the record as
        what it is: an identity whose home is elsewhere."""
        identity = by_sid.get(sid)
        if identity is None:
            identity = get_or_create(
                sid, sid, "foreign_security_principal", IdentityKind.external,
                home=Home.other_tenant, origin="another domain",
            )
            by_sid[sid] = identity
        if not estate.observed(identity):
            estate.observe(identity, sid, sid, raw={"foreign": True})
        return identity

    # Which groups contain each object, transitively, so a member of an
    # inner group is written as a member of every outer one.
    containers: dict[str, set[str]] = {}
    for group in domain.groups:
        for member_sid in group.member_sids:
            containers.setdefault(member_sid, set()).add(group.sid)

    def ancestors(sid: str) -> list[str]:
        out: list[str] = []
        frontier = list(containers.get(sid, ()))
        while frontier:
            current = frontier.pop()
            if current in out or current == sid:
                continue
            out.append(current)
            frontier.extend(containers.get(current, ()))
        return out

    written: set[tuple[int, int]] = set()
    nestings = 0
    for group in domain.groups:
        for member_sid in group.member_sids:
            if member_sid in groups_by_sid:
                db.add(ObservedRelationship(
                    import_id=import_row.id, kind="group_nesting",
                    to_identity_id=by_sid[group.sid].id,
                    from_ref=groups_by_sid[member_sid].sam_account_name, from_kind="group",
                ))
                nestings += 1
            member = by_sid.get(member_sid) or foreign(member_sid)
            for container_sid in [group.sid, *ancestors(group.sid)]:
                key = (member.id, by_sid[container_sid].id)
                if key in written:
                    continue
                written.add(key)
                db.add(Membership(
                    import_id=import_row.id, member_id=member.id,
                    group_id=by_sid[container_sid].id, mode="active",
                ))

    # The built-in groups that hold the domain.
    held: dict[str, RoleDefinition] = {}
    for group in domain.groups:
        document = group_capabilities(group.sid, group.sam_account_name)
        if document is None:
            continue
        definition = role_definition_for(
            db, provider, f"ad:group:{group.sid}", group.sam_account_name, "provider",
            document, import_row, definitions,
        )
        held[group.sid] = definition
        db.add(Grant(
            import_id=import_row.id, identity_id=by_sid[group.sid].id,
            role_definition_id=definition.id, scope_node_id=node.id,
            mode=GrantMode.standing, path=list(DIRECT),
            source_kind="privileged_group", source_ref=group.sid,
        ))

    # Control rights: what a principal can obtain without membership. A
    # principal that already administers the domain gains nothing from
    # a right over a lesser object, so its rights, which the directory
    # grants it over everything by default, are not written.
    standing = {(sid, definition.id) for sid, definition in held.items()}
    administers = {
        sid for sid in held
        if (privileged_capabilities(sid, groups_by_sid[sid].sam_account_name) or (False,))[0]
    }
    domain_definition: RoleDefinition | None = None
    obtainable = 0
    eligible_written: set[tuple[int, int]] = set()
    for ace in domain.aces:
        if ace.inherited or ace.right in READ_ONLY_RIGHTS or ace.principal_sid in administers:
            continue
        if ace.target_sid == domain.sid:
            if domain_definition is None:
                domain_definition = role_definition_for(
                    db, provider, f"ad:domain:{domain.sid}", f"control of {domain.dns_root}",
                    "provider", domain_capabilities(domain.dns_root), import_row, definitions,
                )
            targets = [domain_definition]
            target_name = domain.dns_root
        elif ace.target_sid in held:
            targets = [held[ace.target_sid]]
            target_name = groups_by_sid[ace.target_sid].sam_account_name
        else:
            # A member of a privileged group: owning it is owning the
            # membership. Only direct members, so the claim stays one
            # hop long and readable.
            targets = [
                held[container] for container in containers.get(ace.target_sid, ())
                if container in held
            ]
            if not targets:
                continue
            target = by_sid.get(ace.target_sid)
            target_name = target.first_display_name if target is not None else ace.target_sid
        principal = by_sid.get(ace.principal_sid) or foreign(ace.principal_sid)
        for definition in targets:
            if (ace.principal_sid, definition.id) in standing:
                continue
            key = (principal.id, definition.id)
            if key in eligible_written:
                continue
            eligible_written.add(key)
            db.add(Grant(
                import_id=import_row.id, identity_id=principal.id,
                role_definition_id=definition.id, scope_node_id=node.id,
                mode=GrantMode.eligible,
                path=[{"via": "control_right", "ref": f"{ace.right} on {target_name}",
                       "mode": "eligible"}],
                source_kind="control_right",
                source_ref=f"{ace.right} on {target_name}"[:2048],
            ))
            obtainable += 1

    for trust in domain.trusts:
        db.add(ObservedRelationship(
            import_id=import_row.id, kind="trust", to_identity_id=None,
            from_ref=trust.name, from_kind="domain",
            document={"direction": trust.direction, "type": trust.trust_type,
                      "transitive": trust.forest_transitive},
        ))

    audit.record(
        db,
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        action="snapshot_imported",
        target=f"domain {domain.dns_root}",
        detail=(
            f"source {source_kind}, captured {captured_at.isoformat()}, "
            f"{estate.observations} observations, {estate.new_count} new identities, "
            f"{len(held)} privileged groups, {nestings} nestings, {obtainable} control rights, "
            f"{len(domain.trusts)} trusts"
        ),
    )
    _commit_or_duplicate(db)
    return ImportResult(
        account=domain.dns_root,
        captured_at=captured_at,
        identities_new=estate.new_count,
        identities_known=0,
        observations=estate.observations,
        skipped_rows=domain.skipped,
    )
