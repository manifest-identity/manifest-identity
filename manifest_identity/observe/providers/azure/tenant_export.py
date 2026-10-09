"""The Azure and Entra tenant export parser.

Neither Entra nor Azure ships one export of who holds what, so the
file is one document assembled from Microsoft Graph's own objects and
the Azure command line's own output, each list under a key naming
where it came from (field semantics read from the Graph and Azure CLI
references on September 29, 2026, re-verified at build time):

    tenant                GET /organization: id, displayName, and the
                          cloud (AzureCloud or AzureUSGovernment) the
                          collector ran against
    users                 GET /users with signInActivity: id,
                          userPrincipalName, displayName,
                          accountEnabled, userType (Member or Guest),
                          createdDateTime, signInActivity.
                          lastSignInDateTime; and mfa_registered from
                          the authentication methods registration
                          report (isMfaRegistered), when joined in
    groups                GET /groups, each with GET /groups/{id}/members
                          as a list of id and @odata.type
    service_principals    GET /servicePrincipals: id, appId,
                          displayName, servicePrincipalType
                          (Application, ManagedIdentity, Legacy),
                          accountEnabled, keyCredentials and
                          passwordCredentials (keyId, startDateTime,
                          endDateTime), merged from the application
                          registration where the credentials live
    directory_roles       GET /directoryRoles: id, roleTemplateId,
                          displayName, each with its members
    role_eligibilities    GET /roleManagement/directory/
                          roleEligibilityScheduleInstances:
                          principalId, roleDefinitionId,
                          directoryScopeId, startDateTime, endDateTime
    subscriptions         one per subscription: id, displayName, and
                          role_assignments from
                          az role assignment list --all
                          --include-inherited --scope /subscriptions/ID
                          (principalId, principalName, principalType,
                          roleDefinitionId, roleDefinitionName, scope)
    role_definitions      optional, az role definition list
                          --custom-role-only: name, roleName, roleType,
                          permissions with actions and notActions

The vocabulary ends here; the importer turns these into the neutral
rows. Held to the contract the other parsers set: bounded, in memory,
verified against its own claims, and no error ever repeats file content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from manifest_identity.observe.providers import parsing
from manifest_identity.observe.providers.parsing import ParseError, read_document

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ENTITIES = 100_000
MAX_TEXT_CHARS = 1024

CLOUDS = frozenset({"AzureCloud", "AzureUSGovernment"})
USER_TYPES = frozenset({"Member", "Guest"})
PRINCIPAL_TYPES = frozenset({"User", "Group", "ServicePrincipal", "ForeignGroup", "Unknown"})
SERVICE_PRINCIPAL_TYPES = frozenset({"Application", "ManagedIdentity", "Legacy", "SocialIdp"})
MEMBER_TYPES = {
    "#microsoft.graph.user": "user",
    "#microsoft.graph.group": "group",
    "#microsoft.graph.servicePrincipal": "servicePrincipal",
}

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SCOPE = re.compile(r"^/subscriptions/(?P<subscription>[^/]+)(?:/resourceGroups/(?P<group>[^/]+))?")


_LIMITS = parsing.Limits(max_entries=MAX_ENTITIES, max_text=MAX_TEXT_CHARS)
_list = _LIMITS.read_list
_text = _LIMITS.read_text
_bool = parsing.read_bool
_record = parsing.read_record
_time = parsing.read_time


@dataclass
class ParsedUser:
    id: str
    principal_name: str
    display_name: str
    enabled: bool
    guest: bool
    created: datetime | None
    last_sign_in: datetime | None
    mfa_registered: bool | None


@dataclass
class ParsedMember:
    id: str
    kind: str  # user, group, servicePrincipal


@dataclass
class ParsedGroup:
    id: str
    display_name: str
    members: list[ParsedMember]


@dataclass
class ParsedCredential:
    id: str
    kind: str  # secret or certificate
    start: datetime | None
    end: datetime | None


@dataclass
class ParsedServicePrincipal:
    id: str
    app_id: str | None
    display_name: str
    kind: str  # Application, ManagedIdentity, Legacy, SocialIdp
    enabled: bool
    credentials: list[ParsedCredential]


@dataclass
class ParsedDirectoryRole:
    id: str
    template_id: str
    display_name: str
    members: list[ParsedMember]


@dataclass
class ParsedEligibility:
    principal_id: str
    role_definition_id: str
    scope_id: str
    start: datetime | None
    end: datetime | None


@dataclass
class ParsedAssignment:
    principal_id: str
    principal_name: str | None
    principal_type: str
    role_definition_id: str
    role_name: str
    scope: str
    subscription: str
    resource_group: str | None


@dataclass
class ParsedSubscription:
    id: str
    display_name: str
    assignments: list[ParsedAssignment]


@dataclass
class ParsedRoleDefinition:
    id: str
    name: str
    custom: bool
    actions: list[str]
    not_actions: list[str]


@dataclass
class ParsedTenant:
    id: str
    display_name: str
    government: bool
    users: list[ParsedUser] = field(default_factory=list)
    groups: list[ParsedGroup] = field(default_factory=list)
    service_principals: list[ParsedServicePrincipal] = field(default_factory=list)
    directory_roles: list[ParsedDirectoryRole] = field(default_factory=list)
    eligibilities: list[ParsedEligibility] = field(default_factory=list)
    subscriptions: list[ParsedSubscription] = field(default_factory=list)
    role_definitions: list[ParsedRoleDefinition] = field(default_factory=list)
    skipped: int = 0


def _guid(raw: object, where: str) -> str:
    if not isinstance(raw, str) or not _GUID.match(raw):
        raise ParseError(f"{where}: identifier is not a GUID")
    return raw.lower()


def _members(raw: object, where: str) -> list[ParsedMember]:
    members: list[ParsedMember] = []
    for index, m_raw in enumerate(_list(raw, where)):
        m_where = f"{where}[{index}]"
        member = _record(m_raw, m_where)
        kind = MEMBER_TYPES.get(str(member.get("@odata.type", "")))
        if kind is None:
            raise ParseError(f"{m_where}: a member type is not user, group, or servicePrincipal")
        members.append(ParsedMember(id=_guid(member.get("id"), m_where), kind=kind))
    return members


def _credentials(record: dict[str, object], where: str) -> list[ParsedCredential]:
    out: list[ParsedCredential] = []
    for key, kind in (("passwordCredentials", "secret"), ("keyCredentials", "certificate")):
        for index, c_raw in enumerate(_list(record.get(key), f"{where}.{key}")):
            c_where = f"{where}.{key}[{index}]"
            credential = _record(c_raw, c_where)
            out.append(ParsedCredential(
                id=_guid(credential.get("keyId"), c_where), kind=kind,
                start=_time(credential.get("startDateTime"), c_where),
                end=_time(credential.get("endDateTime"), c_where),
            ))
    return out


def parse_tenant_export(data: bytes) -> ParsedTenant:  # noqa: C901
    document = read_document(data, MAX_FILE_BYTES)

    tenant = _record(document.get("tenant"), "tenant")
    cloud = tenant.get("cloud", "AzureCloud")
    if cloud not in CLOUDS:
        raise ParseError("tenant: cloud is not AzureCloud or AzureUSGovernment")
    parsed = ParsedTenant(
        id=_guid(tenant.get("id"), "tenant"),
        display_name=_text(tenant.get("displayName"), "tenant"),
        government=cloud == "AzureUSGovernment",
    )

    for index, raw in enumerate(_list(document.get("users"), "users")):
        where = f"users[{index}]"
        user = _record(raw, where)
        user_type = user.get("userType", "Member")
        if user_type not in USER_TYPES:
            raise ParseError(f"{where}: userType is not Member or Guest")
        activity = user.get("signInActivity")
        last = None
        if activity is not None:
            last = _time(_record(activity, f"{where}.signInActivity").get("lastSignInDateTime"),
                         where)
        parsed.users.append(ParsedUser(
            id=_guid(user.get("id"), where),
            principal_name=_text(user.get("userPrincipalName"), where),
            display_name=_text(user.get("displayName"), where,
                               str(user.get("userPrincipalName"))),
            enabled=bool(_bool(user.get("accountEnabled"), where, True)),
            guest=user_type == "Guest",
            created=_time(user.get("createdDateTime"), where),
            last_sign_in=last,
            mfa_registered=_bool(user.get("mfa_registered"), where),
        ))

    for index, raw in enumerate(_list(document.get("groups"), "groups")):
        where = f"groups[{index}]"
        group = _record(raw, where)
        parsed.groups.append(ParsedGroup(
            id=_guid(group.get("id"), where),
            display_name=_text(group.get("displayName"), where),
            members=_members(group.get("members"), f"{where}.members"),
        ))

    for index, raw in enumerate(_list(document.get("service_principals"), "service_principals")):
        where = f"service_principals[{index}]"
        principal = _record(raw, where)
        kind = principal.get("servicePrincipalType", "Application")
        if kind not in SERVICE_PRINCIPAL_TYPES:
            raise ParseError(f"{where}: servicePrincipalType is not one the directory defines")
        app_id = principal.get("appId")
        parsed.service_principals.append(ParsedServicePrincipal(
            id=_guid(principal.get("id"), where),
            app_id=None if app_id is None else _guid(app_id, f"{where}.appId"),
            display_name=_text(principal.get("displayName"), where),
            kind=str(kind),
            enabled=bool(_bool(principal.get("accountEnabled"), where, True)),
            credentials=_credentials(principal, where),
        ))

    for index, raw in enumerate(_list(document.get("directory_roles"), "directory_roles")):
        where = f"directory_roles[{index}]"
        role = _record(raw, where)
        parsed.directory_roles.append(ParsedDirectoryRole(
            id=_guid(role.get("id"), where),
            template_id=_guid(role.get("roleTemplateId"), where),
            display_name=_text(role.get("displayName"), where),
            members=_members(role.get("members"), f"{where}.members"),
        ))

    for index, raw in enumerate(_list(document.get("role_eligibilities"), "role_eligibilities")):
        where = f"role_eligibilities[{index}]"
        row = _record(raw, where)
        parsed.eligibilities.append(ParsedEligibility(
            principal_id=_guid(row.get("principalId"), where),
            role_definition_id=_guid(row.get("roleDefinitionId"), where),
            scope_id=_text(row.get("directoryScopeId"), where, "/"),
            start=_time(row.get("startDateTime"), where),
            end=_time(row.get("endDateTime"), where),
        ))

    for index, raw in enumerate(_list(document.get("subscriptions"), "subscriptions")):
        where = f"subscriptions[{index}]"
        subscription = _record(raw, where)
        sub_id = _guid(subscription.get("id"), where)
        assignments: list[ParsedAssignment] = []
        for a_index, a_raw in enumerate(
            _list(subscription.get("role_assignments"), f"{where}.role_assignments")
        ):
            a_where = f"{where}.role_assignments[{a_index}]"
            assignment = _record(a_raw, a_where)
            principal_type = assignment.get("principalType", "Unknown")
            if principal_type not in PRINCIPAL_TYPES:
                raise ParseError(f"{a_where}: principalType is not one the service defines")
            scope = _text(assignment.get("scope"), a_where)
            match = _SCOPE.match(scope)
            if match is None or match.group("subscription").lower() != sub_id:
                raise ParseError(f"{a_where}: scope is not inside this subscription")
            name = assignment.get("principalName")
            assignments.append(ParsedAssignment(
                principal_id=_guid(assignment.get("principalId"), a_where),
                principal_name=None if name is None else _text(name, a_where),
                principal_type=str(principal_type),
                role_definition_id=_text(assignment.get("roleDefinitionId"), a_where)
                .rsplit("/", 1)[-1].lower(),
                role_name=_text(assignment.get("roleDefinitionName"), a_where),
                scope=scope,
                subscription=sub_id,
                resource_group=match.group("group"),
            ))
        parsed.subscriptions.append(ParsedSubscription(
            id=sub_id, display_name=_text(subscription.get("displayName"), where, sub_id),
            assignments=assignments,
        ))

    for index, raw in enumerate(_list(document.get("role_definitions"), "role_definitions")):
        where = f"role_definitions[{index}]"
        definition = _record(raw, where)
        actions: list[str] = []
        not_actions: list[str] = []
        permissions = _list(definition.get("permissions"), f"{where}.permissions")
        for p_index, p_raw in enumerate(permissions):
            permission = _record(p_raw, f"{where}.permissions[{p_index}]")
            for key, target in (("actions", actions), ("notActions", not_actions)):
                for a in _list(permission.get(key), f"{where}.permissions[{p_index}].{key}"):
                    if not isinstance(a, str):
                        raise ParseError(f"{where}: an action must be a string")
                    target.append(a)
        parsed.role_definitions.append(ParsedRoleDefinition(
            id=_text(definition.get("name"), where).rsplit("/", 1)[-1].lower(),
            name=_text(definition.get("roleName"), where),
            custom=definition.get("roleType") == "CustomRole",
            actions=actions, not_actions=not_actions,
        ))

    _verify(parsed)
    return parsed


def _verify(parsed: ParsedTenant) -> None:
    ids = [u.id for u in parsed.users] + [g.id for g in parsed.groups] + [
        s.id for s in parsed.service_principals
    ]
    if len(set(ids)) < len(ids):
        raise ParseError("a principal identifier appears twice")
    known = set(ids)
    for group in parsed.groups:
        for member in group.members:
            if member.id not in known:
                raise ParseError("a group names a member the file does not list")
    for role in parsed.directory_roles:
        for member in role.members:
            if member.id not in known:
                raise ParseError("a directory role names a member the file does not list")
    subscriptions = [s.id for s in parsed.subscriptions]
    if len(set(subscriptions)) < len(subscriptions):
        raise ParseError("a subscription appears twice")
