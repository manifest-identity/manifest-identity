"""The Okta organization export parser.

Okta ships no export of who holds what, so the file is one document
assembled from the management API's own objects, each list under a key
naming the reads it came from, every list paged by the cursor in the
Link header (field semantics read from the Okta management API
reference on September 29, 2026, re-verified at build time):

    org               GET /api/v1/org: id, subdomain
    users             GET /api/v1/users?filter=... for every status:
                      id, status, created, lastLogin, passwordChanged,
                      profile.login, credentials.provider.type; and
                      factors, the active factor types from
                      GET /api/v1/users/{id}/factors, when joined in
    groups            GET /api/v1/groups: id, type, profile.name, each
                      with GET /api/v1/groups/{id}/users as member ids
    role_assignments  GET /api/v1/users/{id}/roles for every user in
                      GET /api/v1/iam/assignees/users, and
                      GET /api/v1/groups/{id}/roles for groups, each
                      with the principal it was read from: id, type,
                      label, status, assignmentType, principal_id
    custom_roles      optional, GET /api/v1/iam/roles with each role's
                      permissions: id, label, permissions
    apps              GET /api/v1/apps: id, label, status, each with
                      GET /api/v1/apps/{id}/users and /groups as
                      assignments of principal_id and scope

A role that reaches a user through a group is listed once against the
group, and the membership hop carries it to the user, rather than once
per user with the group's name lost. The vocabulary ends here.

Held to the contract the other parsers set: bounded, in memory,
verified against its own claims, and no error ever repeats file
content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_ENTITIES = 100_000
MAX_TEXT_CHARS = 1024

USER_STATUSES = frozenset({
    "STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT",
    "SUSPENDED", "DEPROVISIONED",
})
# Statuses in which the account can still be signed into, one way or another.
LIVE_STATUSES = frozenset({"ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT", "PROVISIONED"})
PROVIDER_TYPES = frozenset({"OKTA", "ACTIVE_DIRECTORY", "LDAP", "FEDERATION", "SOCIAL", "IMPORT"})
GROUP_TYPES = frozenset({"OKTA_GROUP", "APP_GROUP", "BUILT_IN"})
ROLE_TYPES = frozenset({
    "SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN", "GROUP_MEMBERSHIP_ADMIN",
    "HELP_DESK_ADMIN", "MOBILE_ADMIN", "READ_ONLY_ADMIN", "REPORT_ADMIN",
    "API_ACCESS_MANAGEMENT_ADMIN", "API_ADMIN", "GROUP_ADMIN", "CUSTOM",
})
ASSIGNMENT_TYPES = frozenset({"USER", "GROUP"})
APP_STATUSES = frozenset({"ACTIVE", "INACTIVE"})

_OKTA_ID = re.compile(r"^[0-9A-Za-z]{20}$")


class ParseError(ValueError):
    """File-level rejection; messages carry rules and names of our own
    contract, never values from the file."""


@dataclass
class ParsedUser:
    id: str
    login: str
    status: str
    provider_type: str
    created: datetime | None
    last_login: datetime | None
    password_changed: datetime | None
    factors: list[str] | None  # None when the export did not join them in


@dataclass
class ParsedGroup:
    id: str
    name: str
    kind: str
    member_ids: list[str]


@dataclass
class ParsedRoleAssignment:
    id: str
    role_type: str
    label: str
    active: bool
    assignment_type: str  # USER or GROUP
    principal_id: str
    custom_role_id: str | None


@dataclass
class ParsedCustomRole:
    id: str
    label: str
    permissions: list[str]


@dataclass
class ParsedAppAssignment:
    principal_id: str
    scope: str  # USER or GROUP


@dataclass
class ParsedApp:
    id: str
    label: str
    active: bool
    assignments: list[ParsedAppAssignment]


@dataclass
class ParsedOrg:
    id: str
    subdomain: str
    users: list[ParsedUser] = field(default_factory=list)
    groups: list[ParsedGroup] = field(default_factory=list)
    role_assignments: list[ParsedRoleAssignment] = field(default_factory=list)
    custom_roles: list[ParsedCustomRole] = field(default_factory=list)
    apps: list[ParsedApp] = field(default_factory=list)
    skipped: int = 0


def _time(raw: object, where: str) -> datetime | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ParseError(f"{where}: a timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"{where}: a timestamp is not ISO 8601") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _okta_id(raw: object, where: str) -> str:
    if not isinstance(raw, str) or not _OKTA_ID.match(raw):
        raise ParseError(f"{where}: identifier is not an Okta identifier")
    return raw


def _text(raw: object, where: str, default: str | None = None) -> str:
    if raw is None and default is not None:
        return default
    if not isinstance(raw, str) or not raw or len(raw) > MAX_TEXT_CHARS:
        raise ParseError(f"{where}: text is missing or longer than {MAX_TEXT_CHARS}")
    if any(ord(c) < 32 for c in raw):
        raise ParseError(f"{where}: text carries a control character")
    return raw


def _list(raw: object, where: str) -> list[object]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ParseError(f"{where}: must be a list")
    if len(raw) > MAX_ENTITIES:
        raise ParseError(f"{where}: more than {MAX_ENTITIES} entries")
    return raw


def _record(raw: object, where: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ParseError(f"{where}: must be an object")
    return raw


def _choice(raw: object, allowed: frozenset[str], where: str, what: str) -> str:
    if not isinstance(raw, str) or raw not in allowed:
        raise ParseError(f"{where}: {what} is not one the API defines")
    return raw


def parse_org_export(data: bytes) -> ParsedOrg:
    if len(data) > MAX_FILE_BYTES:
        raise ParseError(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        document = json.loads(data)
    except ValueError as exc:
        raise ParseError("file is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ParseError("file must be a JSON object")

    org = _record(document.get("org"), "org")
    subdomain = _text(org.get("subdomain"), "org")
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", subdomain):
        raise ParseError("org: subdomain is not a subdomain")
    parsed = ParsedOrg(id=_okta_id(org.get("id"), "org"), subdomain=subdomain)

    for index, raw in enumerate(_list(document.get("users"), "users")):
        where = f"users[{index}]"
        user = _record(raw, where)
        profile = _record(user.get("profile"), f"{where}.profile")
        credentials = user.get("credentials") or {}
        provider = _record(_record(credentials, f"{where}.credentials").get("provider") or
                           {"type": "OKTA"}, f"{where}.credentials.provider")
        factors_raw = user.get("factors")
        factors = None
        if factors_raw is not None:
            factors = [_text(f, f"{where}.factors") for f in _list(factors_raw, f"{where}.factors")]
        parsed.users.append(ParsedUser(
            id=_okta_id(user.get("id"), where),
            login=_text(profile.get("login"), f"{where}.profile"),
            status=_choice(user.get("status", "ACTIVE"), USER_STATUSES, where, "status"),
            provider_type=_choice(provider.get("type", "OKTA"), PROVIDER_TYPES, where,
                                  "credentials.provider.type"),
            created=_time(user.get("created"), where),
            last_login=_time(user.get("lastLogin"), where),
            password_changed=_time(user.get("passwordChanged"), where),
            factors=factors,
        ))

    for index, raw in enumerate(_list(document.get("groups"), "groups")):
        where = f"groups[{index}]"
        group = _record(raw, where)
        profile = _record(group.get("profile"), f"{where}.profile")
        parsed.groups.append(ParsedGroup(
            id=_okta_id(group.get("id"), where),
            name=_text(profile.get("name"), f"{where}.profile"),
            kind=_choice(group.get("type", "OKTA_GROUP"), GROUP_TYPES, where, "type"),
            member_ids=[
                _okta_id(m, f"{where}.members[{m_index}]")
                for m_index, m in enumerate(_list(group.get("members"), f"{where}.members"))
            ],
        ))

    for index, raw in enumerate(_list(document.get("role_assignments"), "role_assignments")):
        where = f"role_assignments[{index}]"
        row = _record(raw, where)
        role_type = _choice(row.get("type"), ROLE_TYPES, where, "type")
        custom = row.get("role")
        if role_type == "CUSTOM" and custom is None:
            raise ParseError(f"{where}: a custom role assignment must name its role")
        parsed.role_assignments.append(ParsedRoleAssignment(
            id=_okta_id(row.get("id"), where),
            role_type=role_type,
            label=_text(row.get("label"), where, role_type),
            active=row.get("status", "ACTIVE") == "ACTIVE",
            assignment_type=_choice(row.get("assignmentType", "USER"), ASSIGNMENT_TYPES, where,
                                    "assignmentType"),
            principal_id=_okta_id(row.get("principal_id"), where),
            custom_role_id=None if custom is None else _text(custom, f"{where}.role"),
        ))

    for index, raw in enumerate(_list(document.get("custom_roles"), "custom_roles")):
        where = f"custom_roles[{index}]"
        row = _record(raw, where)
        permissions = _list(row.get("permissions"), f"{where}.permissions")
        if not all(isinstance(p, str) and p.startswith("okta.") for p in permissions):
            raise ParseError(f"{where}: a permission is not written the way the API writes one")
        parsed.custom_roles.append(ParsedCustomRole(
            id=_text(row.get("id"), where), label=_text(row.get("label"), where),
            permissions=[str(p) for p in permissions],
        ))

    for index, raw in enumerate(_list(document.get("apps"), "apps")):
        where = f"apps[{index}]"
        app = _record(raw, where)
        assignments: list[ParsedAppAssignment] = []
        for a_index, a_raw in enumerate(_list(app.get("assignments"), f"{where}.assignments")):
            a_where = f"{where}.assignments[{a_index}]"
            assignment = _record(a_raw, a_where)
            assignments.append(ParsedAppAssignment(
                principal_id=_okta_id(assignment.get("principal_id"), a_where),
                scope=_choice(assignment.get("scope", "USER"), ASSIGNMENT_TYPES, a_where,
                              "scope"),
            ))
        parsed.apps.append(ParsedApp(
            id=_okta_id(app.get("id"), where),
            label=_text(app.get("label"), where),
            active=_choice(app.get("status", "ACTIVE"), APP_STATUSES, where, "status") == "ACTIVE",
            assignments=assignments,
        ))

    _verify(parsed)
    return parsed


def _verify(parsed: ParsedOrg) -> None:
    users = {u.id for u in parsed.users}
    groups = {g.id for g in parsed.groups}
    if len(users) < len(parsed.users):
        raise ParseError("a user appears twice")
    if len(groups) < len(parsed.groups):
        raise ParseError("a group appears twice")
    known = users | groups
    for group in parsed.groups:
        for member in group.member_ids:
            if member not in users:
                raise ParseError("a group names a member the file does not list as a user")
    for row in parsed.role_assignments:
        if row.principal_id not in known:
            raise ParseError("a role assignment names a principal the file does not list")
        expected = "GROUP" if row.principal_id in groups else "USER"
        if row.assignment_type != expected:
            raise ParseError("a role assignment's type disagrees with its principal")
    custom_ids = {r.id for r in parsed.custom_roles}
    for row in parsed.role_assignments:
        if row.custom_role_id is not None and parsed.custom_roles and (
            row.custom_role_id not in custom_ids
        ):
            raise ParseError("a custom role assignment names a role the file does not describe")
    for app in parsed.apps:
        for assignment in app.assignments:
            if assignment.principal_id not in known:
                raise ParseError("an app assignment names a principal the file does not list")
