"""The GitHub organization export parser.

GitHub ships no single export of who holds what, the way AWS ships the
authorization details file, so the observed side reads one JSON
document assembled from the REST API's own objects. The shape is this
product's, documented here and nowhere else, and each list names the
endpoint whose objects it carries (field semantics verified against
the provider's documentation at build time, September 29, 2026):

    organization           GET /orgs/{org}: login, id
    members                GET /orgs/{org}/members, each joined with
                           GET /orgs/{org}/memberships/{login} for the
                           role (owner or member), the 2fa_disabled
                           filter of the members list for
                           two_factor_enabled, and the newest audit log
                           event per actor for last_active_at, which
                           the members list does not carry
    outside_collaborators  GET /orgs/{org}/outside_collaborators
    teams                  GET /orgs/{org}/teams, each with its members
                           (logins), its parent's slug, and its
                           repositories with the permission level
    repositories           GET /orgs/{org}/repos, each with its direct
                           collaborators and their permission level,
                           and its deploy keys
    installations          GET /orgs/{org}/installations: the app, its
                           permissions map, and its repository selection
    tokens                 GET /orgs/{org}/personal-access-tokens: the
                           fine-grained tokens granted access to the
                           organization, by owner login

The vocabulary ends here. The importer turns these into the neutral
rows every other provider produces, and the rest of the product never
learns the words owner, maintain, or triage.

Held to the contract the AWS parsers set: bounded, in memory, verified
against its own claims, and no error ever repeats file content. Every
identity is keyed by its numeric id, which GitHub never reuses, so a
deleted and recreated login is two identities.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from manifest_identity.observe.providers import parsing
from manifest_identity.observe.providers.parsing import ParseError

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ENTITIES = 50_000
MAX_NAME_CHARS = 255

ORGANIZATION_ROLES = frozenset({"owner", "member", "billing_manager"})
REPOSITORY_PERMISSIONS = frozenset({"admin", "maintain", "write", "triage", "read"})
# An installation's permissions map holds these values per scope.
PERMISSION_LEVELS = frozenset({"read", "write", "admin"})

_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?(?:\[bot\])?$")
_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


_LIMITS = parsing.Limits(max_entries=MAX_ENTITIES, max_text=MAX_NAME_CHARS)
_list = _LIMITS.read_list
_text = _LIMITS.read_text
_bool = parsing.read_bool
_record = parsing.read_record
_time = parsing.read_time


@dataclass
class ParsedMember:
    login: str
    id: int
    role: str
    two_factor_enabled: bool | None
    created_at: datetime | None
    last_active_at: datetime | None


@dataclass
class ParsedCollaborator:
    login: str
    id: int


@dataclass
class ParsedTeam:
    slug: str
    id: int
    name: str
    parent_slug: str | None
    member_logins: list[str]
    repositories: list[tuple[str, str]]  # (repository name, permission)


@dataclass
class ParsedDeployKey:
    id: int
    title: str
    read_only: bool
    created_at: datetime | None
    last_used: datetime | None


@dataclass
class ParsedRepository:
    name: str
    id: int
    visibility: str
    collaborators: list[tuple[str, str]]  # (login, permission), direct only
    deploy_keys: list[ParsedDeployKey]


@dataclass
class ParsedInstallation:
    id: int
    app_slug: str
    app_id: int
    permissions: dict[str, str]
    repository_selection: str
    created_at: datetime | None


@dataclass
class ParsedToken:
    id: int
    owner_login: str
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None
    expired: bool


@dataclass
class ParsedOrganization:
    login: str
    id: int
    members: list[ParsedMember] = field(default_factory=list)
    outside_collaborators: list[ParsedCollaborator] = field(default_factory=list)
    teams: list[ParsedTeam] = field(default_factory=list)
    repositories: list[ParsedRepository] = field(default_factory=list)
    installations: list[ParsedInstallation] = field(default_factory=list)
    tokens: list[ParsedToken] = field(default_factory=list)
    skipped: int = 0


def _int(raw: object, where: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise ParseError(f"{where}: id must be a non-negative integer")
    return raw


def _login(raw: object, where: str) -> str:
    if not isinstance(raw, str) or not _LOGIN.match(raw):
        raise ParseError(f"{where}: login is not a GitHub login")
    return raw


def _slug(raw: object, where: str) -> str:
    if not isinstance(raw, str) or not _SLUG.match(raw):
        raise ParseError(f"{where}: name is not a repository or team name")
    return raw


def _permission(raw: object, where: str) -> str:
    if not isinstance(raw, str) or raw not in REPOSITORY_PERMISSIONS:
        raise ParseError(f"{where}: permission is not one of the five repository levels")
    return raw


def parse_organization_export(data: bytes) -> ParsedOrganization:  # noqa: C901
    if len(data) > MAX_FILE_BYTES:
        raise ParseError(f"file exceeds {MAX_FILE_BYTES} bytes")
    try:
        document = json.loads(data)
    except ValueError as exc:
        raise ParseError("file is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ParseError("file must be a JSON object")

    organization = _record(document.get("organization"), "organization")
    login = _login(organization.get("login"), "organization")
    org = ParsedOrganization(login=login, id=_int(organization.get("id"), "organization"))

    for index, raw in enumerate(_list(document.get("members"), "members")):
        where = f"members[{index}]"
        row = _record(raw, where)
        role = row.get("role", "member")
        if role not in ORGANIZATION_ROLES:
            raise ParseError(f"{where}: role is not owner, member, or billing_manager")
        org.members.append(ParsedMember(
            login=_login(row.get("login"), where),
            id=_int(row.get("id"), where),
            role=str(role),
            two_factor_enabled=_bool(row.get("two_factor_enabled"), where),
            created_at=_time(row.get("created_at"), where),
            last_active_at=_time(row.get("last_active_at"), where),
        ))

    for index, raw in enumerate(
        _list(document.get("outside_collaborators"), "outside_collaborators")
    ):
        where = f"outside_collaborators[{index}]"
        row = _record(raw, where)
        org.outside_collaborators.append(ParsedCollaborator(
            login=_login(row.get("login"), where), id=_int(row.get("id"), where),
        ))

    for index, raw in enumerate(_list(document.get("teams"), "teams")):
        where = f"teams[{index}]"
        row = _record(raw, where)
        parent = row.get("parent")
        repositories: list[tuple[str, str]] = []
        for r_index, r_raw in enumerate(_list(row.get("repositories"), f"{where}.repositories")):
            r_row = _record(r_raw, f"{where}.repositories[{r_index}]")
            repositories.append((
                _slug(r_row.get("name"), f"{where}.repositories[{r_index}]"),
                _permission(r_row.get("permission"), f"{where}.repositories[{r_index}]"),
            ))
        org.teams.append(ParsedTeam(
            slug=_slug(row.get("slug"), where),
            id=_int(row.get("id"), where),
            name=_text(row.get("name", row.get("slug")), where),
            parent_slug=None if parent is None else _slug(parent, f"{where}.parent"),
            member_logins=[
                _login(m, f"{where}.members[{m_index}]")
                for m_index, m in enumerate(_list(row.get("members"), f"{where}.members"))
            ],
            repositories=repositories,
        ))

    for index, raw in enumerate(_list(document.get("repositories"), "repositories")):
        where = f"repositories[{index}]"
        row = _record(raw, where)
        visibility = row.get("visibility", "private")
        if visibility not in ("public", "private", "internal"):
            raise ParseError(f"{where}: visibility is not public, private, or internal")
        collaborators: list[tuple[str, str]] = []
        for c_index, c_raw in enumerate(
            _list(row.get("collaborators"), f"{where}.collaborators")
        ):
            c_where = f"{where}.collaborators[{c_index}]"
            c_row = _record(c_raw, c_where)
            collaborators.append((
                _login(c_row.get("login"), c_where),
                _permission(c_row.get("permission"), c_where),
            ))
        keys: list[ParsedDeployKey] = []
        for k_index, k_raw in enumerate(_list(row.get("deploy_keys"), f"{where}.deploy_keys")):
            k_where = f"{where}.deploy_keys[{k_index}]"
            k_row = _record(k_raw, k_where)
            keys.append(ParsedDeployKey(
                id=_int(k_row.get("id"), k_where),
                title=_text(k_row.get("title", "deploy key"), k_where),
                read_only=bool(_bool(k_row.get("read_only", True), k_where)),
                created_at=_time(k_row.get("created_at"), k_where),
                last_used=_time(k_row.get("last_used"), k_where),
            ))
        org.repositories.append(ParsedRepository(
            name=_slug(row.get("name"), where),
            id=_int(row.get("id"), where),
            visibility=str(visibility),
            collaborators=collaborators,
            deploy_keys=keys,
        ))

    for index, raw in enumerate(_list(document.get("installations"), "installations")):
        where = f"installations[{index}]"
        row = _record(raw, where)
        permissions_raw = row.get("permissions") or {}
        if not isinstance(permissions_raw, dict):
            raise ParseError(f"{where}: permissions must be an object")
        permissions: dict[str, str] = {}
        for scope, level in permissions_raw.items():
            if not isinstance(scope, str) or not _SLUG.match(scope):
                raise ParseError(f"{where}: a permission scope is not a name")
            if level not in PERMISSION_LEVELS:
                raise ParseError(f"{where}: a permission level is not read, write, or admin")
            permissions[scope] = str(level)
        selection = row.get("repository_selection", "selected")
        if selection not in ("all", "selected"):
            raise ParseError(f"{where}: repository_selection is not all or selected")
        org.installations.append(ParsedInstallation(
            id=_int(row.get("id"), where),
            app_slug=_slug(row.get("app_slug"), where),
            app_id=_int(row.get("app_id"), where),
            permissions=permissions,
            repository_selection=str(selection),
            created_at=_time(row.get("created_at"), where),
        ))

    for index, raw in enumerate(_list(document.get("tokens"), "tokens")):
        where = f"tokens[{index}]"
        row = _record(raw, where)
        org.tokens.append(ParsedToken(
            id=_int(row.get("id"), where),
            owner_login=_login(row.get("owner"), where),
            created_at=_time(row.get("created_at"), where),
            expires_at=_time(row.get("expires_at"), where),
            last_used_at=_time(row.get("last_used_at"), where),
            expired=bool(_bool(row.get("token_expired", False), where)),
        ))

    _verify_references(org)
    return org


def _verify_references(org: ParsedOrganization) -> None:  # noqa: C901
    """The file is checked against its own claims: a team member, a
    collaborator, a token owner, a team's parent, and a team's
    repository must each name something the file also lists. A
    reference to nothing is not skipped quietly, because a review that
    silently drops a grant is a review that lies by omission."""
    logins = {m.login for m in org.members} | {c.login for c in org.outside_collaborators}
    member_logins = {m.login for m in org.members}
    slugs = {t.slug for t in org.teams}
    repositories = {r.name for r in org.repositories}
    if len(logins) < len(org.members) + len(org.outside_collaborators):
        raise ParseError("a login appears more than once")
    if len(slugs) < len(org.teams):
        raise ParseError("a team slug appears more than once")
    if len(repositories) < len(org.repositories):
        raise ParseError("a repository name appears more than once")
    for team in org.teams:
        for login in team.member_logins:
            if login not in member_logins:
                raise ParseError("a team names a member the file does not list as a member")
        if team.parent_slug is not None and team.parent_slug not in slugs:
            raise ParseError("a team names a parent the file does not list")
        for name, _ in team.repositories:
            if name not in repositories:
                raise ParseError("a team names a repository the file does not list")
    for repository in org.repositories:
        for login, _ in repository.collaborators:
            if login not in logins:
                raise ParseError("a repository names a collaborator the file does not list")
    for token in org.tokens:
        if token.owner_login not in member_logins:
            raise ParseError("a token names an owner the file does not list as a member")
